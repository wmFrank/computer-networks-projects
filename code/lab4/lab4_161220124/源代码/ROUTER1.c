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
	unsigned char ip1[4] = {192, 168, 3, 1};
	memcpy(route_info[0].destination, ip0, 4);
	memcpy(route_info[0].gateway, ip1, 4);
	char name0[4] = "eth0";
	route_info[0].if_index = get_index(name0);

	unsigned char ip2[4] = {192, 168, 3, 0};
	unsigned char ip3[4] = {192, 168, 3, 1};
	memcpy(route_info[1].destination, ip2, 4);
	memcpy(route_info[1].gateway, ip3, 4);
	char name1[4] = "eth0";
	route_info[1].if_index = get_index(name1);

	unsigned char ip4[4] = {192, 168, 4, 0};
	unsigned char ip5[4] = {192, 168, 4, 2};
	memcpy(route_info[2].destination, ip4, 4);
	memcpy(route_info[2].gateway, ip5, 4);
	char name2[4] = "eth1";
	route_info[2].if_index = get_index(name2);

	unsigned char ip6[4] = {192, 168, 3, 1};
	memcpy(arp_table[0].ip_addr, ip6, 4);

	unsigned char mac0[6] = {0x00, 0x0c, 0x29, 0x6a, 0x51, 0xe2};
	memcpy(arp_table[0].mac_addr, mac0, 6);
	
	unsigned char ip7[4] = {192, 168, 4, 2};
	memcpy(arp_table[1].ip_addr, ip7, 4);
	
	unsigned char mac1[6] = {0x00, 0x0c, 0x29, 0x53, 0x11, 0xb3};
	memcpy(arp_table[1].mac_addr, mac1, 6);

	unsigned char ip8[4] = {192, 168, 3, 2};
	memcpy(device[0].local_ip_addr, ip8, 4);

	unsigned char mac2[6] = {0x00, 0x0c, 0x29, 0x44, 0x35, 0x73};
	memcpy(device[0].local_mac_addr, mac2, 6);

	unsigned char ip9[4] = {192, 168, 4, 1};
	memcpy(device[1].local_ip_addr, ip9, 4);

	unsigned char mac3[6] = {0x00, 0x0c, 0x29, 0x44, 0x35, 0x7d};
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
	int recvpack;
	char recvgram[BUFFER_MAX];

	//recv
	recvpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	while(1)
	{
		// addr中保存了链路层发送端的地址信息
		int recv = recvfrom(recvpack, recvgram, BUFFER_MAX, 0, (struct sockaddr *) &addr, &addr_len);
		if(recv < 64)
		{
			printf ("Fail to recv!!! %x\n", errno);
		}

		char *pt = recvgram;
		struct ipheader *iphead = (struct ipheader *)pt;
	//	printf("%d.%d.%d.%d\n", iphead->dest_ip[0], iphead->dest_ip[1], iphead->dest_ip[2], iphead->dest_ip[3]);
		if(strncmp(iphead->dest_ip, device[0].local_ip_addr, 4) == 0 || strncmp(iphead->dest_ip, device[1].local_ip_addr, 4) == 0)
		{
			printf ("Succeed to recv!!!\n");
		}
		else
		{
			int i;
			for(i = 0; i < MAX_ROUTE_INFO; i++)
			{
				if(strncmp(iphead->dest_ip, route_info[i].destination, 3) == 0)
				{
					printf ("Succeed to recv!!!\n");
					//printf("i = %d\n", i);
					int forward_index = route_info[i].if_index;
					//printf("index = %d\n", forward_index);
					int j;
					for(j = 0; j < MAX_ARP_SIZE; j++)
					{
					//	printf("%d.%d.%d.%d\n", route_info[i].gateway[0], route_info[i].gateway[1], route_info[i].gateway[2], route_info[i].gateway[3]);
						if(strncmp(arp_table[j].ip_addr, route_info[i].gateway, 4) == 0)
						{
						//	printf("j = %d\n", j);
							unsigned char dest_mac_addr[6];
							memcpy(dest_mac_addr, arp_table[j].mac_addr, 6);
						//	printf("dest_mac = %x:%x:%x:%x:%x:%x\n", dest_mac_addr[0], dest_mac_addr[1], dest_mac_addr[2], dest_mac_addr[3], dest_mac_addr[4], dest_mac_addr[5]);
							//send
							int sendpack;
							char sendgram[BUFFER_MAX];
							int datalen;
							int packsize;

							sendpack = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
							struct sockaddr_ll dest_addr = 
							{
								.sll_family = AF_PACKET,
								.sll_protocol = htons(ETH_P_IP),
								.sll_halen = ETH_ALEN,
								.sll_ifindex = forward_index,
							};

							memcpy(&dest_addr.sll_addr, &dest_mac_addr, ETH_ALEN);

							datalen = 64;
							packsize = sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen;
							memset(sendgram, 0, BUFFER_MAX);
							memcpy(sendgram, recvgram, packsize);

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
