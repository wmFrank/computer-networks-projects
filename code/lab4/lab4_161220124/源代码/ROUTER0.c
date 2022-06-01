#include <sys/types.h>    
#include <sys/ioctl.h>    
#include <sys/socket.h>    
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>    
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <stdio.h>    
#include <stdlib.h>    
#include <unistd.h>    
#include <netdb.h>    
#include <string.h>    
#include <fcntl.h>       
#include <errno.h>  
#define BUFFER_MAX 2048

#define MAX_ROUTE_INFO 3
#define MAX_ARP_SIZE 2
#define MAX_DEVICE 2

struct ipheader   //IP头 
{
	unsigned char headlen:4, version:4;
	unsigned char service_type;
	unsigned short total_len;
	unsigned short id;
	unsigned short flag_offset;
	unsigned char ttl;
	unsigned char proto;
	unsigned short head_checksum;
	unsigned char src_ip[4];
	unsigned char dest_ip[4];
};

struct icmpheader {   //ICMP头 
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short int icmp_cksum;
 	unsigned short int icmp_id;
 	unsigned short int icmp_seq;
};

//the information of the static routing table
struct route_item{
	unsigned char destination[4];
	unsigned char gateway[4];
	int if_index;
}route_info[MAX_ROUTE_INFO];

//the informaiton of the " my arp cache"
struct arp_table_item{
	unsigned char ip_addr[4];
	unsigned char mac_addr[6];
}arp_table[MAX_ARP_SIZE];

// the storage of the device , got information from configuration file : if.info
struct device_item{
	unsigned char local_ip_addr[4];
	unsigned char local_mac_addr[6];
}device[MAX_DEVICE];

void Config();
//get if_index
int get_index(char *a);
//compute checksum
unsigned short csum(unsigned short *addr,int len);
//recv & forward
void Recv_Forward();

int main(int argc, char *argv[])  
{  
	Config();
    Recv_Forward();
	return 0;
}  

void Config()
{
	unsigned char ip0[4] = {192, 168, 2, 0};
	unsigned char ip1[4] = {192, 168, 2, 2};
	memcpy(route_info[0].destination, ip0, 4);
	memcpy(route_info[0].gateway, ip1, 4);
	char name0[4] = "eth1";
	route_info[0].if_index = get_index(name0);

	unsigned char ip2[4] = {192, 168, 3, 0};
	unsigned char ip3[4] = {192, 168, 3, 2};
	memcpy(route_info[1].destination, ip2, 4);
	memcpy(route_info[1].gateway, ip3, 4);
	char name1[4] = "eth0";
	route_info[1].if_index = get_index(name1);

	unsigned char ip4[4] = {192, 168, 4, 0};
	unsigned char ip5[4] = {192, 168, 3, 2};
	memcpy(route_info[2].destination, ip4, 4);
	memcpy(route_info[2].gateway, ip5, 4);
	char name2[4] = "eth0";
	route_info[2].if_index = get_index(name2);

	unsigned char ip6[4] = {192, 168, 2, 2};
	memcpy(arp_table[0].ip_addr, ip6, 4);

	unsigned char mac0[6] = {0x00, 0x0c, 0x29, 0xd8, 0x7c, 0xa6};
	memcpy(arp_table[0].mac_addr, mac0, 6);
	
	unsigned char ip7[4] = {192, 168, 3, 2};
	memcpy(arp_table[1].ip_addr, ip7, 4);
	
	unsigned char mac1[6] = {0x00, 0x0c, 0x29, 0x44, 0x35, 0x73};
	memcpy(arp_table[1].mac_addr, mac1, 6);

	unsigned char ip8[4] = {192, 168, 2, 1};
	memcpy(device[0].local_ip_addr, ip8, 4);

	unsigned char mac2[6] = {0x00, 0x0c, 0x29, 0x6a, 0x51, 0xec};
	memcpy(device[0].local_mac_addr, mac2, 6);

	unsigned char ip9[4] = {192, 168, 3, 1};
	memcpy(device[1].local_ip_addr, ip9, 4);

	unsigned char mac3[6] = {0x00, 0x0c, 0x29, 0x6a, 0x51, 0xe2};
	memcpy(device[1].local_mac_addr, mac3, 6);
}

int get_index(char *a)
{
	char if_name[4];
	memcpy(if_name, a, 4);
	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, if_name, IFNAMSIZ - 1);
	int sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	ioctl(sockfd, SIOCGIFINDEX, &req);
	int if_index = req.ifr_ifindex;
	return if_index;
}

unsigned short csum(unsigned short *addr,int len)
{       
	int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    while(nleft > 1)
    {       
		sum += *w++;
    	nleft -= 2;
    }
    if(nleft == 1)
    {       
		*(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

void Recv_Forward()
{
	int recvpack;   //定义的套接字
	char recvgram[BUFFER_MAX];  //接收缓存区
	//recv
	recvpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	struct sockaddr_ll addr;    //用来存储发送方的各方面的信息
	socklen_t addr_len = sizeof(addr);
	while(1)
	{
		// addr中保存了链路层发送端的地址信息
		int recv = recvfrom(recvpack, recvgram, BUFFER_MAX, 0, (struct sockaddr *) &addr, &addr_len);
		if(recv < 64) 
		{
			printf ("Fail to recv!!! %x\n", errno); //检测错误并且输出错误号
		}

		char *pt = recvgram;
		struct ipheader *iphead = (struct ipheader *)pt;
		if(strncmp(iphead->dest_ip, device[0].local_ip_addr, 4) == 0 || strncmp(iphead->dest_ip, device[1].local_ip_addr, 4) == 0)
		{                                           //通过设备信息表来看目的IP是不是自己以确定是否要转发 
			printf ("Succeed to recv!!!\n");
		}
		else
		{
			int i;
			for(i = 0; i < MAX_ROUTE_INFO; i++)
			{
				if(strncmp(iphead->dest_ip, route_info[i].destination, 3) == 0)  //查看路由表对比目的地址
				{
					printf ("Succeed to recv!!!\n");
					int forward_index = route_info[i].if_index;  //得到转发的端口信息
					int j;
					for(j = 0; j < MAX_ARP_SIZE; j++)  
					{
						if(strncmp(arp_table[j].ip_addr, route_info[i].gateway, 4) == 0)  //查看ARP缓存表根据下一条网关找到下一条的MAC地址
						{
							unsigned char dest_mac_addr[6];
							memcpy(dest_mac_addr, arp_table[j].mac_addr, 6);
							//send
							int sendpack;   //发送套接字
							char sendgram[BUFFER_MAX];  //发送的缓存
							int datalen;   //数据区的长度
							int packsize;  //包的总大小

							sendpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
							struct sockaddr_ll dest_addr = 
							{
								.sll_family = AF_PACKET,          //目的地址的类型
								.sll_protocol = htons(ETH_P_IP),  //目的地址的协议
								.sll_halen = ETH_ALEN,            //MAC地址长度
								.sll_ifindex = forward_index,     //发送端口的信息
							};

							memcpy(&dest_addr.sll_addr, &dest_mac_addr, ETH_ALEN);    //将目的MAC地址拷入结构体

							datalen = 64;
							packsize = sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen;
							memset(sendgram, 0, BUFFER_MAX);
							memcpy(sendgram, recvgram, packsize);     //复制包的内容

							if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) //sendto函数发包 
							 	printf ("Fail to send!!! %x\n", errno);
						 	else
								printf ("Succeed to send!!!\n");
							break;
						}
					}
					break;
				}
			}
		}
	}
}