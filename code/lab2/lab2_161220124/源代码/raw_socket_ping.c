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

unsigned short csum(unsigned short *addr,int len);   //计算校验和的子函数 

int main(int argc, char *argv[])
{
	int sendpack;       //发送套接字 
	int recvpack;       //接收套接字 
	char sendgram[BUFFER_MAX];  //发送缓冲区 
	char recvgram[BUFFER_MAX];  //接收缓冲区 
	int datalen;       //发送的数据区长度 
	int packsize;      //发送的包的大小 
	struct sockaddr_in sin;  //定义发送目的地的结构体 
	struct timeval send_tv;  //发送时的时间 
	struct timeval recv_tv;  //接收时的时间 
	struct timeval interval; //计算时间间隔 
	
	//发送ICMP包
	sendpack = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); //指明是ICMP协议 
	datalen = 64;
	struct icmpheader *icmph = (struct icmpheader *) sendgram;
	bzero((&sin), sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[1]); //发送目标的IP地址手动输入 
	memset (sendgram, 0, BUFFER_MAX);   //先将缓冲区清零 
	icmph->icmp_type = 8;              //分别给ICMP头的各项赋值 
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_id = htons(getpid());  //获取系统进程ID 
	icmph->icmp_seq = 0;
	packsize = sizeof(struct icmpheader) + datalen;
	icmph->icmp_cksum = csum((unsigned short *) sendgram, packsize);
 	if (sendto(sendpack, sendgram, packsize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0) //sendto函数发包 
	 	printf ("Fail to send!!!\n");
 	else
		printf ("Succeed to send!!!\n");
	gettimeofday(&send_tv, NULL);   //记录发送的时刻 
	
	//接收ICMP包
	if((recvpack = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)  //recvfrom函数收包 
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
		gettimeofday(&recv_tv, NULL);  //记录接收的时刻 
		interval.tv_sec = recv_tv.tv_sec - send_tv.tv_sec;
		interval.tv_usec = recv_tv.tv_usec - send_tv.tv_usec;
		if(interval.tv_usec < 0)
		{
			interval.tv_sec--;
			interval.tv_usec += 1000000;
		}
		double rtt = ((double)interval.tv_sec) * 1000 +  ((double)interval.tv_usec) / 1000; //相减计算时间间隔并且转换成毫秒 
		unsigned char *p;       //利用字符串指针读取包的内容 
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
		if(icmp->icmp_type == 0 && icmp->icmp_id == icmph->icmp_id)   //通过对比ID以及查看协议类型确实收到的是不是发送的包，如果是则打印收发地址、收发时间间隔等信息 
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
