#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <string.h>
#define BUFFER_MAX 2048

struct ipheader   //IPͷ 
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

struct icmpheader {   //ICMPͷ 
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short int icmp_cksum;
 	unsigned short int icmp_id;
 	unsigned short int icmp_seq;
};

unsigned short csum(unsigned short *addr,int len);   //����У��͵��Ӻ��� 

int main(int argc, char *argv[])
{
	int sendpack;       //�����׽��� 
	int recvpack;       //�����׽��� 
	char sendgram[BUFFER_MAX];  //���ͻ����� 
	char recvgram[BUFFER_MAX];  //���ջ����� 
	int datalen;       //���͵����������� 
	int packsize;      //���͵İ��Ĵ�С 
	struct sockaddr_in sin;  //���巢��Ŀ�ĵصĽṹ�� 
	struct timeval send_tv;  //����ʱ��ʱ�� 
	struct timeval recv_tv;  //����ʱ��ʱ�� 
	struct timeval interval; //����ʱ���� 
	
	//����ICMP��
	sendpack = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); //ָ����ICMPЭ�� 
	datalen = 64;
	struct icmpheader *icmph = (struct icmpheader *) sendgram;
	bzero((&sin), sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[1]); //����Ŀ���IP��ַ�ֶ����� 
	memset (sendgram, 0, BUFFER_MAX);   //�Ƚ����������� 
	icmph->icmp_type = 8;              //�ֱ��ICMPͷ�ĸ��ֵ 
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_id = htons(getpid());  //��ȡϵͳ����ID 
	icmph->icmp_seq = 0;
	packsize = sizeof(struct icmpheader) + datalen;
	icmph->icmp_cksum = csum((unsigned short *) sendgram, packsize);
 	if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0) //sendto�������� 
	 	printf ("Fail to send!!!\n");
 	else
		printf ("Succeed to send!!!\n");
	gettimeofday(&send_tv, NULL);   //��¼���͵�ʱ�� 
	
	//����ICMP��
	if((recvpack = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)  //recvfrom�����հ� 
	{
		printf("Fail to create raw socket!!!\n");
		return -1;
	}
	while(1)
	{
		int recv = recvfrom(recvpack, recvgram, BUFFER_MAX, 0, NULL, NULL);
		if(recv < 42)
		{
			printf("Fail to receive!!!\n");
			break;
		}
		gettimeofday(&recv_tv, NULL);  //��¼���յ�ʱ�� 
		interval.tv_sec = recv_tv.tv_sec - send_tv.tv_sec;
		interval.tv_usec = recv_tv.tv_usec - send_tv.tv_usec;
		if(interval.tv_usec < 0)
		{
			interval.tv_sec--;
			interval.tv_usec += 1000000;
		}
		double rtt = ((double)interval.tv_sec) * 1000 +  ((double)interval.tv_usec) / 1000; //�������ʱ��������ת���ɺ��� 
		unsigned char *p;       //�����ַ���ָ���ȡ�������� 
		p = recvgram;
		p += 14;
		struct ipheader *ip = (struct ipheader *)p;
		int iplen = ip->headlen * 4;
		struct icmpheader *icmp = (struct icmpheader *)(p + iplen);
		struct ipheader ip_head;
		int i;
		for(i = 0; i < 4; i++)
			ip_head.src_ip[i] = p[i + 12];
		for(i = 0; i < 4; i++)
			ip_head.dest_ip[i] = p[i + 16];
		if(icmp->icmp_type == 0 && icmp->icmp_id == icmph->icmp_id)   //ͨ���Ա�ID�Լ��鿴Э������ȷʵ�յ����ǲ��Ƿ��͵İ�����������ӡ�շ���ַ���շ�ʱ��������Ϣ 
		{
			printf("Succeed to receive!!!\n");
			printf("From: %d.%d.%d.%d\n  To: %d.%d.%d.%d\n",ip_head.src_ip[0],ip_head.src_ip[1],ip_head.src_ip[2],ip_head.src_ip[3],ip_head.dest_ip[0],ip_head.dest_ip[1],ip_head.dest_ip[2],ip_head.dest_ip[3]);
			printf(" rtt: %.3f ms\n", rtt);
			break;
		}
	}	
	return 0; 
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
