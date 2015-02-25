#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>


/*给定一个网络接口名,找出对应网络接口的默认网关地址
   通过读取/proc/net/route文件来寻找默认网关,返回-1表示未找到
   最好的方法是用netlink来实现的,但是这里没有*/
int getgateway(struct sockaddr *gateway,char *ifi_name)
{
	FILE *f;
	char str[200];

	if(!(f=fopen("/proc/net/route","r"))){
		fprintf(stderr,"open /proc/net/route error:%s\n",strerror(errno));
		exit(1);
	}
	while(fgets(str,sizeof(str),f)){
		char *t=str,*ifi,*dst,*gtw;
		unsigned int dstaddr;

		while(!((*t>='0'&&*t<='9')||(*t>='A'&&*t<='Z')||(*t>='a'&&*t<='z')))
			t++;
		ifi=t;
		while((*t>='0'&&*t<='9')||(*t>='A'&&*t<='Z')||(*t>='a'&&*t<='z'))
			t++;
		*(t++)='\0';
		dst=t;
		if(strcmp(ifi,ifi_name))
			continue;
		while((*t>='0'&&*t<='9')||(*t>='A'&&*t<='Z')||(*t>='a'&&*t<='z'))
			t++;
		*(t++)='\0';
		gtw=t;
		sscanf(dst,"%x",&dstaddr);
		if(dstaddr)
			continue;
		while((*t>='0'&&*t<='9')||(*t>='A'&&*t<='Z')||(*t>='a'&&*t<='z'))
			t++;
		*(t++)='\0';
		sscanf(gtw,"%x",&(((struct sockaddr_in *)gateway)->sin_addr.s_addr));
		fclose(f);
		return(0);
	}
	fclose(f);
	return(-1);
}
/*
int
main()
{
	char ifi_name[20];
	struct sockaddr_in gateway;
	
	scanf("%s",ifi_name);
	if(getgateway((struct sockaddr *)&gateway,ifi_name)<0)
		err_quit("no gateway!");
	printf("%s\n",inet_ntoa(gateway.sin_addr.s_addr));
}
*/
