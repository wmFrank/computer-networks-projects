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

#define MAX_ROUTE_INFO 2
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

void repack(char *buffer, int buffer_len);

void unpack(char *buffer, int buffer_len);

int main(int argc, char *argv[])  
{  
	Config();
    Recv_Forward();
	return 0;
}  

void Config()
{
	unsigned char ip0[4] = {10, 0, 0, 0};
	unsigned char ip1[4] = {10, 0, 0, 1};
	memcpy(route_info[0].destination, ip0, 4);
	memcpy(route_info[0].gateway, ip1, 4);
	char name0[4] = "eth0";
	route_info[0].if_index = get_index(name0);

	unsigned char ip2[4] = {172, 0, 0, 0};
	unsigned char ip3[4] = {192, 168, 0, 1};
	memcpy(route_info[1].destination, ip2, 4);
	memcpy(route_info[1].gateway, ip3, 4);
	char name1[4] = "eth1";
	route_info[1].if_index = get_index(name1);

	unsigned char ip6[4] = {10, 0, 0, 2};
	memcpy(arp_table[0].ip_addr, ip6, 4);

	unsigned char mac0[6] = {0x00, 0x0c, 0x29, 0x44, 0x35, 0x73};
	memcpy(arp_table[0].mac_addr, mac0, 6);
	
	unsigned char ip7[4] = {192, 168, 0, 1};
	memcpy(arp_table[1].ip_addr, ip7, 4);
	
	unsigned char mac1[6] = {0x00, 0x0c, 0x29, 0x53, 0x11, 0xb3};
	memcpy(arp_table[1].mac_addr, mac1, 6);

	unsigned char ip8[4] = {10, 0, 0, 1};
	memcpy(device[0].local_ip_addr, ip8, 4);

	unsigned char mac2[6] = {0x00, 0x0c, 0x29, 0xd8, 0x7c, 0xa6};
	memcpy(device[0].local_mac_addr, mac2, 6);

	unsigned char ip9[4] = {192, 168, 0, 2};
	memcpy(device[1].local_ip_addr, ip9, 4);

	unsigned char mac3[6] = {0x00, 0x0c, 0x29, 0xd8, 0x7c, 0xb0};
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
//		printf("recv ======== %d\n", recv);
		if(recv < 48) 
		{
			printf ("Fail to recv!!! %x\n", errno); //检测错误并且输出错误号
		}
	/*	else
		{
			printf ("Succeed to recv!!! \n");
		}*/

		char *pt = recvgram;
		struct ipheader *iphead = (struct ipheader *)pt;
		unsigned char address[4] = {10, 0, 1, 2};
		if(strncmp(iphead->dest_ip, device[1].local_ip_addr, 4) == 0)
		{
			unpack(recvgram, recv);
		}
		else if(strncmp(iphead->dest_ip, address, 4) == 0)
		{
			repack(recvgram, recv);
		}
	}
}

void repack(char *buffer, int buffer_len)
{
	int sendpack;
	char sendgram[BUFFER_MAX];
	int datalen;
	int packsize;

	char name[4] = "eth1";
	int if_index = get_index(name);

	//send
	sendpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	struct sockaddr_ll dest_addr = 
	{
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_halen = ETH_ALEN,
		.sll_ifindex = if_index,
	};
	unsigned char dest_mac_addr[6];
	unsigned char dest_ip_addr[4] = {172, 0, 0, 2};
	int i;
	for(i = 0; i < MAX_ROUTE_INFO; i++)
	{
		if(strncmp(dest_ip_addr, route_info[i].destination, 3) == 0)
		{
			int j;
			for(j = 0; j < MAX_ARP_SIZE; j++)
			{
				if(strncmp(route_info[i].gateway, arp_table[j].ip_addr, 4) == 0)
				{
					memcpy(dest_mac_addr, arp_table[j].mac_addr, 6);
					break;
				}
			}
			break;
		}
	}

	memcpy(&dest_addr.sll_addr, &dest_mac_addr, ETH_ALEN);

	datalen = buffer_len;
	memset(sendgram, 0, BUFFER_MAX);
	memcpy(sendgram + sizeof(struct ipheader) + sizeof(struct icmpheader), buffer, datalen);
	char *p = sendgram;

	struct ipheader *iph = (struct ipheader*) p;
	iph->headlen = 0x5;
	iph->version = 0x4;
	iph->service_type = 0x0;
	iph->total_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen);
	iph->id = 0x1;
	iph->flag_offset = 0x0;
	iph->ttl = 64;
	iph->proto = 0x1;
	iph->head_checksum = 0;
	memcpy(iph->src_ip, device[1].local_ip_addr, 4);
	memcpy(iph->dest_ip, dest_ip_addr, 4);
	iph->head_checksum = csum((unsigned short *)p, sizeof(struct ipheader));

	p += 20;
	struct icmpheader *icmph = (struct icmpheader *) p;
	icmph->icmp_type = 0;              //分别给ICMP头的各项赋值 
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_id = htons(getpid());  //获取系统进程ID 
	icmph->icmp_seq = 0;
	icmph->icmp_cksum = csum((unsigned short *) p, sizeof(struct icmpheader) + datalen);

	packsize = sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen;
	if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) //sendto函数发包 
	 	printf ("Fail to send!!! %x\n", errno);
 	else
		printf ("Succeed to repack and send!!!\n");
}

void unpack(char *buffer, int buffer_len)
{
	int sendpack;
	char sendgram[BUFFER_MAX];
	int datalen;
	int packsize;

	char name[4] = "eth0";
	int if_index = get_index(name);

	//send
	sendpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	struct sockaddr_ll dest_addr = 
	{
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_halen = ETH_ALEN,
		.sll_ifindex = if_index,
	};
	unsigned char dest_mac_addr[6];
	unsigned char dest_ip_addr[4] = {10, 0, 0, 2};
	int i;
	for(i = 0; i < MAX_ROUTE_INFO; i++)
	{
		if(strncmp(dest_ip_addr, route_info[i].destination, 3) == 0)
		{
			int j;
			for(j = 0; j < MAX_ARP_SIZE; j++)
			{
				if(strncmp(route_info[i].gateway, arp_table[j].ip_addr, 4) == 0)
				{
					memcpy(dest_mac_addr, arp_table[j].mac_addr, 6);
					break;
				}
			}
			break;
		}
	}

	memcpy(&dest_addr.sll_addr, &dest_mac_addr, ETH_ALEN);

	datalen = buffer_len - (sizeof(struct ipheader) + sizeof(struct icmpheader));
	memset(sendgram, 0, BUFFER_MAX);
	memcpy(sendgram, buffer + sizeof(struct ipheader) + sizeof(struct icmpheader), datalen);

	packsize = datalen;
	if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) //sendto函数发包 
	 	printf ("Fail to send!!! %x\n", errno);
 	else
		printf ("Succeed to unpack and send!!!\n");
}
