#include "unpifi.h"

#define TYPE_NONE 0x0000U
#define TYPE_ARPFLOOD 0x0001U
#define TYPE_IPCONFLICT 0x0002U
#define TYPE_SNIFFER 0x0004U
#define TYPE_ARPDECEIVE 0x0008U
#define TYPE_RECOVER 0x0010U
#define TYPE_VM 0x0020U
#define TYPE_SCAN 0x0040U
#define NUMBER_OF_TYPE 7/*攻击类型的个数*/

#define OPT_NONE 0x0000U
#define OPT_TIMESLOT 0x00001U
#define OPT_EXCLUSIVE 0x00002U
#define OPT_INTERFACE 0x00004U
#define OPT_SNIFFER 0x00008U
#define OPT_ONE_END 0x00010U
#define OPT_ANOTHER_END 0x00020U
#define OPT_MATCH 0x00040U
#define OPT_NUMBER 0x00080U
#define OPT_HOSTS 0x00100U
#define NUMBER_OF_OPT 9/*选项个数*/

#define HOSTS_NUMBER 50	

struct ipmac{
	struct in_addr ipaddr;
	char haddr[IFI_HADDR];
	struct ipmac *next;
};

struct vm{/*伪造的虚拟主机的ip地址范围和伪造的mac地址*/
	u_int32_t hoststart;
	u_int32_t hostend;
	char haddr[IFI_HADDR];
	struct vm *next;
};

struct pthread_vm_param{
	int ifindex;
	struct vm *vmhead;
};










