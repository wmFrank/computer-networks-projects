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

#define MAX_ARP_SIZE 1

const unsigned char dest_ip_addr[4] = {192, 168, 4, 2};

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

//the informaiton of the " my arp cache"
struct arp_table_item{
	unsigned char ip_addr[4];
	unsigned char mac_addr[6];
}arp_table[MAX_ARP_SIZE];

unsigned char local_ip_addr[4];
unsigned char local_mac_addr[6];
unsigned char gateway[4]; 

//config 
void Config();
//get if_index
int get_index(char *a);
//compute checksum
unsigned short csum(unsigned short *addr,int len);
//send
void Send();
//recv
void Recv();

int main(int argc, char *argv[])  
{  
	  Config();
      Send();
      Recv();
      return 0;
}  

void Config()
{
	unsigned char ip0[4] = {192, 168, 2, 1};
	memcpy(arp_table[0].ip_addr, ip0, 4);

	unsigned char mac0[6] = {0x00, 0x0c, 0x29, 0x6a, 0x51, 0xec};
	memcpy(arp_table[0].mac_addr, mac0, 6);
	
	unsigned char ip1[4] = {192, 168, 2, 2};
	memcpy(local_ip_addr, ip1, 4);
	
	unsigned char mac1[6] = {0x00, 0x0c, 0x29, 0xd8, 0x7c, 0xa6};
	memcpy(local_mac_addr, mac1, 6);

	unsigned char ip2[4] = {192, 168, 2, 1};
	memcpy(gateway, ip2, 4);
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

void Send()
{
	int sendpack;
	char sendgram[BUFFER_MAX];
	int datalen;
	int packsize;

	//get interface index
	/*const char *if_name = "eth0";
	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, if_name, IFNAMSIZ - 1);
	int sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	ioctl(sockfd, SIOCGIFINDEX, &req);
	int if_index = req.ifr_ifindex;*/
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
	if(strncmp(dest_ip_addr, local_ip_addr, 3) == 0)
	{
		int i;
		for(i = 0; i < MAX_ARP_SIZE; i++)
		{
			if(strcmp(dest_ip_addr, arp_table[i].ip_addr) == 0)
			{
				memcpy(dest_mac_addr, arp_table[i].mac_addr, 6);
				break;
			}
		}
	}
	else
	{
		int i;
		for(i = 0; i < MAX_ARP_SIZE; i++)
		{
			if(strcmp(gateway, arp_table[i].ip_addr) == 0)
			{
				memcpy(dest_mac_addr, arp_table[i].mac_addr, 6);
				break;
			}
		}
	}

	memcpy(&dest_addr.sll_addr, &dest_mac_addr, ETH_ALEN);

	datalen = 64;
	memset(sendgram, 0, BUFFER_MAX);
	char *p = sendgram;

	struct ipheader *iph = (struct ipheader*) p;
	iph->headlen = 0x5;
	iph->version = 0x4;
	iph->service_type = 0x0;
	iph->total_len = sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen;
	iph->id = 0x1;
	iph->flag_offset = 0x0;
	iph->ttl = 64;
	iph->proto = 0x1;
	iph->head_checksum = 0;
	memcpy(iph->src_ip, local_ip_addr, 4);
	memcpy(iph->dest_ip, dest_ip_addr, 4);
	iph->head_checksum = csum((unsigned short *)p, sizeof(struct ipheader));

	p += 20;
	struct icmpheader *icmph = (struct icmpheader *) p;
	icmph->icmp_type = 8;              //分别给ICMP头的各项赋值 
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_id = htons(getpid());  //获取系统进程ID 
	icmph->icmp_seq = 0;
	icmph->icmp_cksum = csum((unsigned short *) sendgram, sizeof(struct icmpheader) + datalen);

	packsize = sizeof(struct ipheader) + sizeof(struct icmpheader) + datalen;
	if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) //sendto函数发包 
	 	printf ("Fail to send!!! %x\n", errno);
 	else
		printf ("Succeed to send!!!\n");
}

void Recv()
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
		//printf("%d.%d.%d.%d\n", iphead->dest_ip[0], iphead->dest_ip[1], iphead->dest_ip[2], iphead->dest_ip[3]);
		pt += 20;
		struct icmpheader *icmphead = (struct icmpheader *)pt;

		if(strncmp(iphead->dest_ip, local_ip_addr, 4) == 0 && icmphead->icmp_type == 0x0)
		{
			printf ("Succeed to recv!!!\n");
		}
	}
}