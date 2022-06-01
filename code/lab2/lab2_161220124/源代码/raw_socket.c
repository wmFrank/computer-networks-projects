#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

struct Ether_head //以太头 
{
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned short frame_type;
};

struct IP_head  //IP头 
{
	unsigned char version_headlen;
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

struct ARP_head  //ARP头 
{
	unsigned short hard_type;
	unsigned short proto_type;
	unsigned char hard_addr_len;
	unsigned char proto_addr_len;
	unsigned short op;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
};

int main(int argc,char* argv[])
{
	int sock_fd;  //接收包的套接字 
	int recv;      
	char buffer[BUFFER_MAX]; //用于存放包的字符串数组 
	unsigned char *p;  //访问字符串的指针变量 
	if((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  //设置的是ETH_P_ALL，意思接收所有类型的包 
	{
		printf("error create raw socket\n");
		return -1;
	}
	while(1)
	{
		recv = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);  //recvfrom函数捕获包 
		if(recv < 42)
		{
			printf("error when recv msg \n");
			return -1;
		}
		p = buffer;
		struct Ether_head ether_head; //定义以太头结构，捕获MAc收发地址，以及捕获协议类型参数 
		int i;
		for(i = 0; i < 6; i ++)
			ether_head.dest_mac[i] = p[i];
		for(i = 0; i < 6; i ++)
			ether_head.src_mac[i] = p[i + 6];
		ether_head.frame_type = (p[12] << 8) + p[13];
		p += 14;
		printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x ==> %02x:%02x:%02x:%02x:%02x:%02x\n",ether_head.src_mac[0],ether_head.src_mac[1],ether_head.src_mac[2],ether_head.src_mac[3],ether_head.src_mac[4],ether_head.src_mac[5],ether_head.dest_mac[0],ether_head.dest_mac[1],ether_head.dest_mac[2],ether_head.dest_mac[3],ether_head.dest_mac[4],ether_head.dest_mac[5]);
		if(ether_head.frame_type == 0x0800) //判断是IP包，则输出IP地址和协议类型 
		{	
			struct IP_head ip_head;
			int i;
			for(i = 0; i < 4; i++)
				ip_head.src_ip[i] = p[i + 12];
			for(i = 0; i < 4; i++)
				ip_head.dest_ip[i] = p[i + 16];
			ip_head.proto = p[9];
			printf("IP:%d.%d.%d.%d ==> %d.%d.%d.%d\n",ip_head.src_ip[0],ip_head.src_ip[1],ip_head.src_ip[2],ip_head.src_ip[3],ip_head.dest_ip[0],ip_head.dest_ip[1],ip_head.dest_ip[2],ip_head.dest_ip[3]);
			printf("Protocol:");
			switch(ip_head.proto)
			{
				case IPPROTO_ICMP:printf("ICMP\n");break;
				case IPPROTO_IGMP:printf("IGMP\n");break;
				case IPPROTO_IPIP:printf("IPIP\n");break;
				case IPPROTO_TCP:printf("TCP\n");break;
				case IPPROTO_UDP:printf("UDP\n");break;
				default:printf("Pls query yourself\n");
			}
		}
		else if(ether_head.frame_type == 0x0806) //判断是ARP包，输出IP地址和协议类型 
		{
			struct ARP_head arp_head;
			int i;
			for(i = 0; i < 4; i++)
				arp_head.src_ip[i] = p[i + 14];
			for(i = 0; i < 4; i++)
				arp_head.dest_ip[i] = p[i + 24];
			printf("IP:%d.%d.%d.%d ==> %d.%d.%d.%d\n",arp_head.src_ip[0],arp_head.src_ip[1],arp_head.src_ip[2],arp_head.src_ip[3],arp_head.dest_ip[0],arp_head.dest_ip[1],arp_head.dest_ip[2],arp_head.dest_ip[3]);
			printf("Protocol:ARP\n");
		}
	}
	return -1;
}
