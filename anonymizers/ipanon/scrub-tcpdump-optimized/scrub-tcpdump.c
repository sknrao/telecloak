//./scrub-tcpdump -r /home2/students/asym_traces/miffy/tcp_all.cap -w test -k 998 -o "srcip rp dscip rp payload h1"
#ifndef __linux__
  #define SCRUB_BSD_HEADERS
#endif

#define DEBUG_MODE_ON 0

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#ifdef SCRUB_BSD_HEADERS
  #include <net/if.h>
#endif
#include <netinet/if_ether.h>
//#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <regex.h>
#include "md5.h"
#include "checksum.h"

#define TSA_T 8 /* only 8 works right now */ 
#define TSA_S 13 
#define TSA_R 500
#define TSA_B 32

#define ENCAP_ETHERNET 1
#define NET_IPV4 0x0008 
#define NET_LOOP 0x0090 

#define REGEX_URL_STRING "https?://[a-zA-Z0-9.-_]+"

#define swap16(p) ((((p)&(0xff00)) >> 8) | (((p)&(0x00ff)) << 8))
#define swap32(p) 	(swap16(((p)&(0xffff0000u)) >> 16) |\
				 	(swap16((p)&(0x0000ffff)) << 16))
#define trunc(X,B) X = (((X) << (B)) >> (B))
#define rand8(X) X = (rand() / (RAND_MAX / 0xffu + 1))
#define rand16(X) X = (rand() / (RAND_MAX / 0xffffu + 1))
#define rand32(X) X = (rand() / (RAND_MAX / 0xffffffffu + 1))



#ifdef SCRUB_BSD_HEADERS
  #define tot_len    ip_len
  #define saddr      ip_src.s_addr
  #define daddr      ip_dst.s_addr
  #define protocol   ip_p
  #define ttl        ip_ttl
  #define check      ip_sum
  #define tos        ip_tos
  #define ihl        ip_hl
  #define iphdr ip
  #define UDP_SOURCE udp->uh_sport
  #define UDP_DEST   udp->uh_dport
  #define UDP_CHECK  udp->uh_sum
  #define UDP_LEN    udp->uh_ulen
  #define TCP_SOURCE tcp->th_sport
  #define TCP_DEST   tcp->th_dport
  #define TCP_SEQ    tcp->th_seq
  #define TCP_ACK    tcp->th_ack
  #define TCP_FLAGS  tcp->th_flags
  #define TCP_WIN    tcp->th_win
  #define TCP_CHECK  tcp->th_sum
  #define TCP_URG    tcp->th_urg
  #define TCP_OFF    tcp->th_off
#else
  #define UDP_SOURCE udp->source
  #define UDP_DEST   udp->dest
  #define UDP_CHECK  udp->check
  #define UDP_LEN    udp->len
  #define TCP_SOURCE tcp->source
  #define TCP_DEST   tcp->dest
  #define TCP_SEQ    tcp->seq
  #define TCP_ACK    tcp->ack_seq
  #define TCP_FLAGS  tcp->flags
  #define TCP_WIN    tcp->window
  #define TCP_CHECK  tcp->check
  #define TCP_URG    tcp->urg_ptr
  #define TCP_OFF    tcp->doff
#endif

/* initialization of anonymization options */
int recalculate_checksum = 1;
int tcp_recalculate_checksum = 1;
int udp_recalculate_checksum = 1;
int eth_on = 0, ipv4_on = 0, tcp_on = 0, udp_on = 0; /* checks */
int user_key_int=0;

int tsenum = 0;
static int timestamp = -1; 
int ts_rand_up = 0;
int ts_rand_down = 0;
int enumcnt = 0;
static int pktlen = -1;
static int iplen = -1;
static int pktcaplen = -1;

static int ethsrcaddr = -1;
static int ethdstaddr = -1;
static int nettype = -1; 

static int transportprotocol = -1;
static int srcip = -1;
static int dstip = -1;
static int ipoptions = -1;
static int ttl = -1;
static int fragflags = -1;

static int tcpsrcport = -1;
static int tcpdstport = -1; 
static int udpsrcport = -1;
static int udpdstport = -1; 
static int tcpflags = -1;
static int tcpwindow = -1;
static int tcpoptions = -1;
static int sequence = -1;
static int iptos = -1;

static int payload = -1; 
int sec = 0, usec = 0, randtime;

md5_byte_t user_key_md5[16];

regex_t re;
regmatch_t pm[0];

int Qsize;
struct timeq_st { 
	struct pcap_pkthdr *header;
	u_char *packet;
	struct timeq_st *next;
	struct timeq_st *prev;
};
typedef struct timeq_st timeq;
timeq *Qfront, *Qback;

unsigned int subtree_hash_num;
unsigned char **pre_trees;
unsigned char **sub_trees;
/* for now the top hash will only be 8 bits tall */
unsigned char *top_hash;

int checkArrSrc[256],checkArrDst[256];
int mapTable[256];
void checkerInit()
{
	if(!DEBUG_MODE_ON)
		return;
	int i;
	for(i=0;i<256;++i)
		checkArrSrc[i]=checkArrDst[i]=0;
}

void checkerPrint()
{
	if(!DEBUG_MODE_ON)
		return;
	int i;
	int count=0;
	for(i=0;i<256;++i)
	{
		if(checkArrDst[i]==0)
			count++;
		printf("%d : %d , %d\n",i,checkArrSrc[i],checkArrDst[i]);
	}
	printf("0-> %d\n",count);
}

unsigned int mix(unsigned int a, unsigned int b, unsigned int c)
{
  a=a-b;  a=a-c;  a=a^(c >> 13);
  b=b-c;  b=b-a;  b=b^(a << 8); 
  c=c-a;  c=c-b;  c=c^(b >> 13);
  a=a-b;  a=a-c;  a=a^(c >> 12);
  b=b-c;  b=b-a;  b=b^(a << 16);
  c=c-a;  c=c-b;  c=c^(b >> 5);
  a=a-b;  a=a-c;  a=a^(c >> 3);
  b=b-c;  b=b-a;  b=b^(a << 10);
  c=c-a;  c=c-b;  c=c^(b >> 15);
  return c;
}

void generateMap()
{
	int i;
	if(payload==10)
	{
		// 1 to 1
		int count,set,index;
		count=set=index=0;
		for(i=0;i<256;++i)
			mapTable[i]=-1;
		for(i=0;i<256;++i)
		{
			index+=user_key_int;
			index%=256;
			while(mapTable[index]!=-1)
			{
				++index;
				if(index==256)
					index=0;
			}
			mapTable[index]=i;
		}
	}
	else
	{
		//mix
		srand ( time(NULL) );
		int random = rand();
		for(i=0;i<256;++i)
			mapTable[i]=mix(i,user_key_int,random)%256;
	}
	if(!DEBUG_MODE_ON)
		return;
	for(i=0;i<256;++i)
	{
		printf("%d , %d\n",i,mapTable[i]);
	}
	
}
/* 
 * This function handles the calling of the anonymization in question
 */
void anonymize(void (*f)(unsigned char *, int, unsigned char *), unsigned char *addr, int bytes, unsigned char *extopt) {
	f(addr,bytes,extopt);
}

unsigned char doMapping(unsigned char input)
{
	if(DEBUG_MODE_ON)
	{
		checkArrSrc[(int)input]++;
		checkArrDst[(int)mapTable[input]]++;
	}
	return (unsigned char)mapTable[(int)input];
}

void anonymizePayload(int payload, unsigned char *addr, int bytes, unsigned char *extopt) {

	int i;
	for(i=0;i<bytes; ++i)
		addr[i]=doMapping(addr[i]);
}

/* 
 * This initializes all of the data structures
 * for the TSA algorithm.
 */
void prefix_preserving_init() {
	int h = 1<<(TSA_B-TSA_S-TSA_T-3), i, j; 
	unsigned char s[16] = {85, 86, 89, 90, 101, 102, 105, 106, 149, 150, 153, 154, 165, 166, 169, 170};
	unsigned char tmp;
	top_hash = (unsigned char *)malloc((1<<TSA_T)*sizeof(unsigned char));
	if (top_hash == NULL)
		perror("malloc of top_hash");
	pre_trees = (unsigned char **)malloc((1<<TSA_T)*sizeof(unsigned char *));
	if (pre_trees == NULL)
		perror("malloc of pre_trees");
	/* make the main trees */
	for (i = 0; i < (1<<TSA_T); ++i) {
		top_hash[i] = i;
		pre_trees[i] = (unsigned char *)malloc(h);
		if (pre_trees[i] == NULL)
			perror("malloc of pre_trees");
		for (j = 0; j < h; ++j)
			pre_trees[i][j] = s[rand() / (RAND_MAX / 16 + 1)];
	}
	/* shuffle the top hash */
	/* and create subtrees */
	sub_trees = (unsigned char **)malloc(TSA_R*sizeof(unsigned char *));
	if (sub_trees == NULL)
		perror("malloc of sub_trees");
	for (i = 0; i < TSA_R; ++i) {
		j = rand() / (RAND_MAX / (1<<TSA_T) + 1);
		tmp = top_hash[i];
		top_hash[i] = top_hash[j];
		top_hash[j] = tmp;
		sub_trees[i] = (unsigned char *)malloc((1<<TSA_S)/8);
		if (sub_trees[i] == NULL)
			perror("malloc of sub_trees");
		for (j = 0; j < ((1<<TSA_S)/8); ++j) 
			sub_trees[i][j] = s[rand() / (RAND_MAX / 16 + 1)]; 
	}
	/* generate a hashing number to decide what subtree goes where */
	subtree_hash_num = rand();
}


unsigned int tree_trav(unsigned char *tree, unsigned int *swap_value, int height) {
	unsigned char finder = 64;
	unsigned int pos = 1, tree_value = 0;
	int i;
	for (i = 0; i < height; ++i) {
		tree_value |= ((*tree)&finder)>0; 
		pos += 2*i+((*swap_value)&1u); 
		tree += (int)((1<<i)/8);
		finder = 128>>(pos%8);
		*swap_value >>= 1;
		tree_value <<= 1;
	}
	return tree_value>>1;
}
/* 
 * This draws on the precalculated tree for the Ramaswamy prefix-preserving TSA system
 */
void prefix_preserving(uint32_t *in_value, int size, unsigned char *extopts) {
	int i, tmp = 0;	
	uint32_t tree_value, swap_value = *in_value;

	for (i = 0; i < TSA_T; ++i) {
		tmp <<= 1;
		tmp |= swap_value&1u;
		swap_value >>= 1;
	}
	tree_value = top_hash[tmp];
	tree_value |= tree_trav(pre_trees[tmp],&swap_value,(TSA_B-TSA_S-TSA_T))<<TSA_T;
	tree_value |= tree_trav(sub_trees[(tree_value^subtree_hash_num)%TSA_R],&swap_value,TSA_S)<<(TSA_B-TSA_S);
	(*in_value) ^= tree_value;
	
}
/*
 * This preforms bilateral classification.
 */
void bilateral_classification(unsigned char *data, int bytes, unsigned char *extopts) {
	int i;
	for (i = 0; i < bytes; ++i) {
		if (*(data+i)>*(extopts+i)) {
			memset(data,0xff,bytes);
			return;
		} else if (*(data+i)<*(extopts+i)) {
			memset(data,0,bytes);
			return;
		}
	}
	memset(data,0,bytes);
}

/* 
 * This function just generates a purely random number
 */
void randomize(unsigned char *data, int bytes, unsigned char *extopts) {
	int i;
	for (i = 0; i < bytes; ++i) 
		*(data+i) = rand() / (RAND_MAX / 256 + 1);
}

/* 
 * Handles pseudo-random permutation based on MD5 hashing
 * I think this is way to costly, especially for small fields 
 * use HMACs in the future for small fields
 */
void random_permute(unsigned char *data, int bytes, unsigned char *extopts) {
	int i;
	md5_state_t state;
	md5_byte_t digest[16];
	md5_init(&state);
	for (i = 0; i < bytes; ++i) 
		*(data+i) ^= user_key_md5[(i+*(extopts+i))%bytes];
	md5_append(&state,(const md5_byte_t *)data,bytes);
	md5_finish(&state,digest);
	memcpy(data,digest,bytes);
}

/* 
 * This function handles "grouping" operations.
 * Grouping is always done exponentially by powers of 2.
 */
void grouping_exp(unsigned char *data, int bytes, unsigned char *extopts) {
	int match = 0x100, i; 
	for (i = bytes-1; i >= 0; --i) {
		if (match != 0x100)
			*(data+i) = 0;
		else 
			for (match = 1; match < 0xff; match<<=1)
				if (match & *(data+i)) {
					*(data+i) = match;
					break;
				}
	}	
}

/*
 * Linear grouping with extopts as size of interval (only for 2 byte items now) 
 */
void grouping(unsigned char *data, int bytes, unsigned char *extopts) {
    *data = swap16(swap16(*data)-swap16(*data)%(*extopts));
}

/*
 * The black marker function
 */
void black_marker(unsigned char *data, int bytes, unsigned char *extopt) {
	if (extopt != NULL) {
		memcpy(data,extopt,bytes);
		return;
	}
	memset(data,0,bytes);
}

/* 
 * Truncation
 */
void truncate(unsigned char *data, int bytes, unsigned char *extopt) { 
	while (*extopt>=8) {
		*data++=0;
		*extopt>>=3;
	}
	trunc(*data,*extopt);
}

/* 
 * This eleminates anything in the given regex
 */
void regex_elim(unsigned char *packet, int bytes, unsigned char *extopt) {	
	char *tst;
	tst = (char *)malloc(bytes);
	if (tst == NULL)
		perror("malloc of tst (during regex)");
	memcpy(tst,packet,bytes);
	while (0 == regexec(&re, tst, 1, pm, 0)) {
		memset(packet+pm[0].rm_so,'\0',pm[0].rm_eo-pm[0].rm_so);
		tst+=pm[0].rm_eo;
		packet+=pm[0].rm_eo;
	}
}

/* 
 * This handles a time queue similiar to the unix
 * time system for the enumeration method.
 */
void timequeue(u_char *user, struct pcap_pkthdr *header, u_char *packet) {
	timeq *curr, *prev = NULL;
	timeq *new = (timeq *)malloc(sizeof(timeq));
	if (new == NULL)
		perror("malloc of timeq new");
	new->header = header;
	new->packet = packet;
	if (!Qfront) {
		Qback = new;
		new->next = Qfront;
		Qfront = new;
	} else { 
		curr = Qfront;
		while (curr) {
			if ((curr->header->ts.tv_sec < header->ts.tv_sec) || ((curr->header->ts.tv_sec == header->ts.tv_sec) && (curr->header->ts.tv_usec <= header->ts.tv_usec)))
				break;
			prev = curr;
			curr = curr->next;
		}
		if (curr) {
			new->next = curr;
			curr->prev = new;
			if (!prev)
				Qfront = new;
		} else {
			prev->next = new;
			new->prev = prev;	
			Qback = new;
		}
	}
	if (++Qsize > 100) {
		Qback->header->ts.tv_sec = enumcnt++;
		Qback->header->ts.tv_usec = 0;
		pcap_dump(user, Qback->header, Qback->packet);
		Qback = Qback->prev;	
		free(Qback->next->header);
		free(Qback->next->packet);
		free(Qback->next);
		--Qsize;
	}
}

/*
 * random window
 */
void random_window(unsigned char *packet, int bytes, unsigned char *extopts) {
	// window: (ts_rand_up-ts_rand_down)*(rand()/RAND_MAX)+ts_rand_down;

}

/* 
 * This function handles TCP headers.
 */
int FIN = 0, SYN = 0, RST = 0, PSH = 0, URG = 0, ACK = 0;
void TCP(u_char *packet, int length_rest, struct iphdr *iph) { 
	struct tcphdr *tcp = (struct tcphdr *)(packet);
	unsigned short port = 4; /* 1024 byte reversed.. */

	switch (tcpsrcport) {
		case 0:
			TCP_SOURCE = 0; /* black marker */
			break;
		case 1:
			random_permute((unsigned char *)&TCP_SOURCE,2,(unsigned char *)&port);
			break;
		case 4:
			bilateral_classification((unsigned char *)&TCP_SOURCE,2,(unsigned char *)&port);
			break;
		case 5:
			rand16(TCP_SOURCE);
			break;
		default: break;
	}
		
	switch (tcpdstport) {
		case 0:
			TCP_DEST = 0; /* black marker */
			break;
		case 1:
			random_permute((unsigned char *)&TCP_DEST,2,(unsigned char *)&port);
			break;
		case 4:
			bilateral_classification((unsigned char *)&TCP_DEST,2,(unsigned char *)&port);
			break;
		case 5:
			rand16(TCP_DEST);
			break;
		default: break;
	}
	switch (tcpwindow) {
		case 0:
			if (sec)
				TCP_WIN = 0xFFFFu;
			else
				TCP_WIN = 0; /* black marker */
			break;
		case 1:
			random_permute((unsigned char *)&TCP_WIN,2,(unsigned char *)&port);
			break;
		case 4:
			bilateral_classification((unsigned char *)&TCP_WIN,2,(unsigned char *)&tcpwindow);
			break;
		case 5:
			rand16(TCP_WIN);
			break;
		case 9:
			if (swap16(TCP_WIN) < 1025) TCP_WIN = swap16(1024);
			else if (swap16(TCP_WIN) < 8193) TCP_WIN = swap16(8192);
			else if (swap16(TCP_WIN) < 16385) TCP_WIN = swap16(16384);
			else if (swap16(TCP_WIN) < 32769) TCP_WIN = swap16(32768);
			else TCP_WIN = swap16(65535); 
			break;
		default: break;
	}


	switch (tcpflags) { 
		case 0:
#ifdef SCRUB_BSD_HEADERS
			if (FIN) TCP_FLAGS = TCP_FLAGS & (!TH_FIN);
			else if (SYN) TCP_FLAGS &= !TH_SYN;
			else if (RST) TCP_FLAGS &= !TH_RST;
			else if (PSH) TCP_FLAGS &= !TH_PUSH;
			else if (ACK) TCP_FLAGS &= !TH_ACK;
			else if (URG) TCP_FLAGS &= !TH_URG;
#else
			if (FIN) tcp->fin = 0;
			else if (SYN) tcp->syn = 0;
			else if (RST) tcp->rst = 0;
			else if (PSH) tcp->psh = 0;
			else if (ACK) tcp->ack = 0;
			else if (URG) tcp->urg = 0;
#endif
			else *(packet+13) = 0;
			break;
		case 1: {
				unsigned char t = 0x73;
				random_permute(packet+13,1,&t);
				*(packet+13)&=0x3fu;
			}
			break;
		case 5:
			rand8(*(packet+13));
			*(packet+13)&=0x3fu;
			break;
		case 9: {
#ifdef SCRUB_BSD_HEADERS
			if (FIN) TCP_FLAGS &= (!TH_FIN & !TH_SYN & !TH_RST);
			if (ACK) TCP_FLAGS &= (!TH_ACK & !TH_PUSH & !TH_URG);
#else
			if (FIN) { tcp->fin = 0; tcp->syn = 0; tcp->rst = 0; }
			if (ACK) { tcp->ack = 0; tcp->psh = 0; tcp->urg = 0; }
#endif
		}
		default: break;
		
	}
	
	switch (sequence) {
		case 0:
			if (sec) 
				TCP_SEQ = swap32(1);
			else if (usec)
				TCP_SEQ = 0xffffffffu;
			else 
				TCP_SEQ = 0;
			break;
		case 1:
			random_permute((unsigned char *)&TCP_SEQ,4,(unsigned char *)&sequence);
			break;
		case 5:
			rand32(TCP_SEQ); 
			break;
		case 9:
			if (TCP_SEQ < swap32(1000001)) TCP_SEQ = swap32(1000000);  
			else if (TCP_SEQ < swap32(2000001)) TCP_SEQ = swap32(2000001);
			else if (TCP_SEQ < swap32(3000001)) TCP_SEQ = swap32(3000000);
			else  TCP_SEQ = swap32(4000000);
			break;
		default: break;
	}

	switch (tcpoptions) {
		case 0:
			black_marker(packet+21,(TCP_OFF)*4-20,NULL);
			break;
		case 1:
			random_permute(packet+21,(TCP_OFF)*4-20,NULL);
			break;
		case 5:
			randomize(packet+21,(TCP_OFF)*4-20,NULL);
			break;
		default: 
			break;
	}

	// for payload
	if (payload){
		//anonymize(payload,packet+tcp->doff*4,length_rest-tcp->doff*4,NULL);
		anonymizePayload(payload,packet+tcp->doff*4,length_rest-tcp->doff*4,NULL);
	}

	if (tcp_recalculate_checksum) { 
		TCP_CHECK = 0;
		TCP_CHECK = my_tcp_check(tcp,
			length_rest>ntohs(iph->tot_len)-4*iph->ihl?
				ntohs(iph->tot_len)-4*iph->ihl:length_rest,
			iph->saddr,iph->daddr); 
	}
}

/* 
 * This function handles UDP packet headers.
 */
void UDP(u_char *packet, int length_rest, struct iphdr *iph) { 
	struct udphdr *udp = (struct udphdr *)(packet);
	unsigned short port = 4;

	switch (tcpsrcport) {
		case 0:
			UDP_SOURCE = 0; /* black marker */
			break;
		case 1:
			random_permute((unsigned char *)&UDP_SOURCE,2,(unsigned char *)&port);
			break;
		case 4:
			bilateral_classification((unsigned char *)&UDP_SOURCE,2,(unsigned char *)&port);
			break;
		case 5:
			rand16(UDP_SOURCE);
			break;
		default: break;
	}
	switch (udpdstport) {
		case 0:
			UDP_DEST = 0; /* black marker */
			break;
		case 1:
			random_permute((unsigned char *)&UDP_DEST,2,(unsigned char *)&port);
			break;
		case 4:
			bilateral_classification((unsigned char *)&UDP_DEST,2,(unsigned char *)&port);
			break;
		case 5:
			rand16(UDP_DEST);
			break;
		default: break;
	}

/*
	if (payload != NULL)
		anonymize(payload,packet+8,length_rest-8,NULL);
*/

	if (udp_recalculate_checksum) { 
		UDP_CHECK = 0;
		UDP_CHECK = my_udp_check((void *)udp,
			ntohs(UDP_LEN),
			iph->saddr,iph->daddr);
	}
}

/* 
 * This function handles the IPv4 packet headers.
 */
void IPv4(u_char *packet, int length_rest) {
	struct iphdr *ipv4 = (struct iphdr *)(packet);
	unsigned int blackip = 0x101010a;
	switch (srcip) {
		case 0:
			ipv4->saddr = 0x101010a;
			break;
		case 1:
			random_permute((unsigned char *)&ipv4->saddr,4,(unsigned char *)&blackip);
			break;
		case 2:
			prefix_preserving((uint32_t *)&ipv4->saddr,4,(unsigned char *)&blackip);
			break;
		case 5:
			rand32(ipv4->saddr);
			break;
		default: break;
	}

	switch (dstip) {
		case 0:
			ipv4->daddr = 0x101010a;
			break;
		case 1:
			random_permute((unsigned char *)&ipv4->daddr,4,(unsigned char *)&blackip);
			break;
		case 2:
			prefix_preserving((uint32_t *)&ipv4->daddr,4,(unsigned char *)&blackip);
			break;
		case 5:
			rand32(ipv4->daddr);
			break;
		default: break;
	}
	switch (fragflags) {
		case 0:
			if (sec)
				*(packet+6) = 0xE0u;
			else
				*(packet+6) = 0x00u;
			break;
		case 1: 
			random_permute(packet+6,1,(unsigned char *)&fragflags);
			*(packet+6)&=0xE0;
			break;
		case 5:
			rand8(*(packet+6));
			*(packet+6)&=0xE0;
			break;
		default: break;
	}

	switch (iptos) {
		case 0:
			ipv4->tos = 0;
			break;
		case 1:
			random_permute((unsigned char *)&ipv4->tos,1,(unsigned char *)&iptos);
			break;
		case 4:
			if (ipv4->tos&0x80) ipv4->tos = 0xff;
			else ipv4->tos = 9;
			break;
		case 5:
			rand8(ipv4->tos);
			break;
		default: break;
	}

	switch (ipoptions) {
		case 0:
			black_marker(packet+20,((ipv4->ihl<<2)-20),NULL);
			break;
		case 5:
			randomize(packet+20,((ipv4->ihl<<2)-20),NULL);
			break;
		default: break;
	}
	
	switch (ttl) {
		case 0: 
			ipv4->ttl = 0;
			break;
		case 1:
			random_permute((unsigned char *)&ipv4->ttl,1,(unsigned char *)&ttl);
			break;
		case 5:
			rand8(ipv4->ttl);
			break;
		case 9:
			if (ipv4->ttl == 0) ipv4->ttl = 0;
			else if (ipv4->ttl < 33) ipv4->ttl = 32;
			else if (ipv4->ttl < 65) ipv4->ttl = 64;
			else ipv4->ttl = 255; 
			break;
		default: break;
	}

	switch (ipv4->protocol) {
		case IPPROTO_TCP:
			if (tcp_on)
				TCP(packet+ipv4->ihl*4,length_rest-ipv4->ihl*4,ipv4);
			break;
		case IPPROTO_UDP:
			if (udp_on)
				UDP(packet+ipv4->ihl*4,length_rest-ipv4->ihl*4,ipv4);
			break;
		case IPPROTO_ICMP:
			break;
		default:
			/* printf("Protocol %d unknown\n",ipv4->protocol); */
			break;
	}
	
	unsigned char transp = 0xffu;
	switch (transportprotocol) {
		case 0:
			ipv4->protocol = 0xfeu;
			break;
		case 1:
			random_permute(&ipv4->protocol,1,&transp);
			break;
		case 4:
			if (1 == ipv4->protocol || 17 == ipv4->protocol 
				|| 6 == ipv4->protocol)
				ipv4->protocol = 253;
			else 
				ipv4->protocol = 254;
			break;
		case 5:
			rand8(ipv4->protocol);
			break;
		default: break;
	}

	switch (iplen) {
		case 0:
			ipv4->tot_len = 0;
			break;
		case 1:
			random_permute((unsigned char *)&ipv4->tot_len,2,(unsigned char *)&pktlen);
			break;
		case 5:
			rand16(ipv4->tot_len);
			break;
		case 9:
    		ipv4->tot_len = ipv4->tot_len-ipv4->tot_len%10;
			break;
		default: break;
	}
		

	if (recalculate_checksum) {
		ipv4->check = 0;
		ipv4->check = ip_fast_csum((u_char *) ipv4,ipv4->ihl);
	}
}

/*
 * This function handles Ethernet hardware layer packets.
 */
void eth(u_char *packet, int length) {
	struct ether_header *eth = (struct ether_header *)(packet); 

	switch (ethdstaddr) {
		case 0:
			memset(packet,0,6);
			break;
		default: break;
	}
	switch (ethsrcaddr) {
		case 0:
			memset(packet+6,0,6);
			break;
		default: break;
	}
			
	switch (eth->ether_type) {
		case NET_IPV4:
			if (ipv4_on) 
				IPv4(packet+14,length-14);
			break;
		case NET_LOOP:
			break;
		default:
			break;
	}

	switch (nettype) {
		case 0:
			memset(packet+12,0,2);
			break;
		default: break;
	}
}
/* 
 * This function is designed to be a callback function for
 * pcap_loop(). 
 */
void anon_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	struct pcap_pkthdr *newheader = (struct pcap_pkthdr *)header;
	unsigned char *newpacket = (unsigned char *)packet;

	switch (1/* p->linktype */) {
		case ENCAP_ETHERNET:
			eth(newpacket, header->caplen);
			break;
		default:
			break;
	} 
	/* unsigned short midlen = 0x6400; */

				uint16_t t = swap16(10);
	switch (pktlen) { 
		case 0:
			newheader->len = 0;
			break;
		case 1:
			random_permute((unsigned char*)&newheader->len,2,(unsigned char *)&t);
			break;
		case 5:
			rand16(newheader->len);
			break;
		case 9:
    		newheader->len = newheader->len-newheader->len%10;
			break;
		default: break;
	}

	/* newheader->caplen -- */
	int tsss = 4;

	switch (timestamp) {
		case 0:
			if (!usec) 
				newheader->ts.tv_sec = 0;
			if (!sec)
				newheader->ts.tv_usec = 0;
			break;
		case 1:
			random_permute((unsigned char *)&newheader->ts.tv_sec,4,(unsigned char *)&tsss);
			random_permute((unsigned char *)&newheader->ts.tv_usec,4,(unsigned char *)&tsss);
			break;
		case 5:
			rand32(newheader->ts.tv_sec); 
			rand32(newheader->ts.tv_usec);
			break;
		case 7:
			if (!usec)
                newheader->ts.tv_sec -= newheader->ts.tv_sec%10000;
            if (!sec)
                newheader->ts.tv_usec -= newheader->ts.tv_usec%10000;
			break;
		case 8:
			newheader->ts.tv_sec += randtime;
			break;
		default: break;
	}

	if (tsenum) {
		newheader = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
		if (newheader == NULL)
			perror("malloc of newheader");
		memcpy(newheader,header,sizeof(struct pcap_pkthdr));
		newpacket = (u_char *)malloc(sizeof(u_char)*newheader->caplen);
		if (newpacket == NULL)
			perror("malloc of newpacket");
		memcpy(newpacket,packet,sizeof(u_char)*newheader->caplen);
		timequeue(user, newheader, newpacket);
	} else
		pcap_dump(user, newheader, newpacket);
}

/*
 * I still really don't know how to do options for this thing
 * it should be done in such a way that it can be integrated into tcpdump
 * this is all just temporary..... (no error checking or anything)
 */

void parse_options(char *options) {
	int i, j, k, s = 0, l = 0;
	char in_fields[10][100], in_functions[10][100]; 
	memset(in_fields,'\0',10*100);
	memset(in_functions,'\0',10*100);
	for (i = 0; i < strlen(options)+1; ++i) { 
		for (j = i; j < strlen(options)+1; ++j) {
			if (options[j] == ' ' || j == strlen(options)) {
				if (!s)
					strncpy(in_fields[l],options+i,j-i);
				if (s)
					strncpy(in_functions[l++],options+i,j-i);
				s = !s;
				i = j;
				break;
			}
		}
	}
	int num_fields = 24, num_functions = 12, ppi = 0;	
	char st_fields[][20] = {"srcip", 
							"dstip", 
							"ipoptions", 
							"transportprotocol",
							"nettype",
							"timestamp",
							"pktlen",
							"pktcaplen",
							"ethsrcaddr",
							"ethdstaddr",
							"tcpsrcport",
							"tcpdstport",
							"udpsrcport",
							"udpdstport",
							"tcpflags",
							"tcpoptions",
							"payload",
							"iplen",
							"ttl",
							"tcpwindow",
							"fragflags",
							"sequence",
							"iptos"};
	/*void *vo_functions[] = {black_marker, 
							random_permute, 
							prefix_preserving, 
							timequeue, 
							bilateral_classification, 
							randomize, 
							regex_elim,
							truncate,
							random_window,
							grouping};*/ 
	char st_functions[][3] = {	"bm", "rp", "pp", "en", "bi", 
								"ra", "re", "tr", "rw", "gr",
								"h1","h2"};
	void **vo_fields;
	vo_fields = malloc(num_fields*sizeof(void *));
	if (vo_fields == NULL)
		perror("malloc vo_fields");
	memset(vo_fields,'\0',num_fields);
	for (i = 0; i < l+1; ++i)
		for (j = 0; j < num_fields; ++j)
			if (!strcmp(in_fields[i],st_fields[j]))
				for (k = 0; k < num_functions; ++k)
					if ((in_functions[i][0] == st_functions[k][0]) && 
						(in_functions[i][1] == st_functions[k][1])) {
						if (0 == j)  { srcip = k; ++ipv4_on; }
						if (1 == j)  { dstip = k; ++ipv4_on; }
						if (2 == j)  { ipoptions = k; ++ipv4_on; }
						if (3 == j)  { transportprotocol = k; ++ipv4_on; }
						if (4 == j)  { nettype = k; }
						if (5 == j)  { timestamp = k; if (in_functions[i][2]=='s') sec++; if(in_functions[i][2]=='u') usec++; }
						if (6 == j)  { pktlen = k; }
						if (7 == j)  { pktcaplen = k; }
						if (8 == j)  { ethsrcaddr = k; }
						if (9 == j)  { ethdstaddr = k; }
						if (10 == j) { tcpsrcport = k; ++tcp_on; ++ipv4_on; }
						if (11 == j) { tcpdstport = k; ++tcp_on; ++ipv4_on; }
						if (12 == j) { udpsrcport = k; ++udp_on; ++ipv4_on; }
						if (13 == j) { udpdstport = k; ++udp_on; ++ipv4_on; }
						if (14 == j) { tcpflags = k;   ++tcp_on; ++ipv4_on; }
						if (15 == j) { tcpoptions = k; ++tcp_on; ++ipv4_on; }
						if (16 == j) { payload = k; ++tcp_on; ++udp_on; ++ipv4_on; generateMap();}
						if (17 == j) { iplen = k; ++ipv4_on; }
						if (18 == j) { ttl = k; ++ipv4_on; }
						if (19 == j) { tcpwindow = k; ++ipv4_on; ++tcp_on; }
						if (20 == j) { fragflags = k; ++ipv4_on; } 
						if (21 == j) { sequence = k; ++ipv4_on; ++tcp_on; }
						if (22 == j) { iptos = k; ++ipv4_on; }
						if (2 == k) ppi++;
						if (3 == k) tsenum++;
/*
						if (8 == k) {
							int z;
						 	char *str;
							for (z = 2; (in_functions[i][z] != '\0' ||
										 in_functions[i][z] != ':'); ++z);
							str  = (char *)malloc(z-1);
							memcpy(str,&in_functions[i][z],z-2);
							ts_rand_down = atoi(str);
							free(str);
							for (z = 2; (in_functions[i][z] != '\0' ||
										 in_functions[i][z] != ':'); ++z);
							str  = (char *)malloc(z-1);
							memcpy(str,&in_functions[i][z],z-2);
							ts_rand_down = atoi(str);
							free(str);
						}
*/
						if (14 == j) {
							if (in_functions[i][2] == 'F') FIN++;
							if (in_functions[i][2] == 'S') SYN++;
							if (in_functions[i][2] == 'R') RST++;
							if (in_functions[i][2] == 'P') PSH++;
							if (in_functions[i][2] == 'A') ACK++;
							if (in_functions[i][2] == 'U') URG++;
						}
					}
	if (ppi) prefix_preserving_init();
	rand32(randtime);
/*
 *  (note to self: get formal training in program architecture and input methodology)
 * 		field function <--- went with this for now 
 *	functions
 * 		bm -> black marker
 * 		rp -> rand permute / keyed randomization
 * 		pp -> prefix preserving
 * 		en -> enumeration
 * 		bi -> bilateral classification
 * 		pp -> prefix preserving
 * 		ra -> pure randomization
 * 		re -> regex catchall
 * 		trN -> truncate N bits 
 * 		rwN:M -> random window uniform [N:M]
 * 		gr -> grouping
 * 	fields
 * 		srcip
 * 		dstip
 * 		etc
 */
}

/*
void print_options() {
	if (eth_on) {
		printf("-------------ethernet packet--------------\n");
		printf("| preamble | dest addr | src addr | type |\n");
		printf("| -------- |\n");
		print_op(eth_dst_addr,11);
		print_op(eth_src_addr,10);
		print_op(net_type,6);
		printf("\n");
		printf("------------------------------------------\n");
	}
}
*/

/*
 * This function performs all initialization.
 * In the future this will take some form of 
 * arguements as options.  Isn't the future great?
 */
void scrub_init(char *options, char *user_key) { 
	/* in the future this function will handle parsing of cmd line options */
	user_key_int=atoi(user_key);
	parse_options(options);
	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)user_key, strlen(user_key));
	md5_finish(&state, user_key_md5);
	
	srand(time(0));
	checkerInit();
	regcomp(&re, REGEX_URL_STRING, REG_EXTENDED);
	/* do all final error checking */
}
void scrub_end(u_char *user) {
	if (tsenum) {
		while (Qsize-- > 0) {
			Qback->header->ts.tv_sec = enumcnt++;
			Qback->header->ts.tv_usec = 0;
			pcap_dump(user, Qback->header, Qback->packet);
			Qback = Qback->prev;
		}
	}
	checkerPrint();
}

