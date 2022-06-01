#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

struct Ether_head //��̫ͷ 
{
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned short frame_type;
};

struct IP_head  //IPͷ 
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

struct ARP_head  //ARPͷ 
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
	int sock_fd;  //���հ����׽��� 
	int recv;      
	char buffer[BUFFER_MAX]; //���ڴ�Ű����ַ������� 
	unsigned char *p;  //�����ַ�����ָ����� 
	if((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  //���õ���ETH_P_ALL����˼�����������͵İ� 
	{
		printf("error create raw socket\n");
		return -1;
	}
	while(1)
	{
		recv = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);  //recvfrom��������� 
		if(recv < 42)
		{
			printf("error when recv msg \n");
			return -1;
		}
		p = buffer;
		struct Ether_head ether_head; //������̫ͷ�ṹ������MAc�շ���ַ���Լ�����Э�����Ͳ��� 
		int i;
		for(i = 0; i < 6; i ++)
			ether_head.dest_mac[i] = p[i];
		for(i = 0; i < 6; i ++)
			ether_head.src_mac[i] = p[i + 6];
		ether_head.frame_type = (p[12] << 8) + p[13];
		p += 14;
		printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x ==> %02x:%02x:%02x:%02x:%02x:%02x\n",ether_head.src_mac[0],ether_head.src_mac[1],ether_head.src_mac[2],ether_head.src_mac[3],ether_head.src_mac[4],ether_head.src_mac[5],ether_head.dest_mac[0],ether_head.dest_mac[1],ether_head.dest_mac[2],ether_head.dest_mac[3],ether_head.dest_mac[4],ether_head.dest_mac[5]);
		if(ether_head.frame_type == 0x0800) //�ж���IP���������IP��ַ��Э������ 
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
		else if(ether_head.frame_type == 0x0806) //�ж���ARP�������IP��ַ��Э������ 
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
