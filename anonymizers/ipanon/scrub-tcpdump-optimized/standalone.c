#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "scrub-tcpdump.h"

int main(int argc, char **argv) { 
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	pcap_dumper_t *p;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	char *user_key, *read_file, *write_file, *iface, *options, filter[] = "";
	pcap_t *ps;
	int op, iflag = 0, rflag = 0, kflag = 0, wflag = 0;

	while ((op = getopt(argc,argv,":f:i:k:o:r:w:")) != EOF) {
		switch (op) {
			case 'f':
				strcat(filter,optarg);
				break;
			case 'i':
				++iflag;
				iface = optarg;
				break;
			case 'r':
				++rflag;
				read_file = optarg;
				break;
			case 'w':
				write_file = optarg;
				++wflag;
				break;
			case 'k':
				user_key = optarg;
				++kflag;
				break;
			case 'o':
				options = optarg;
				break;
			default:
				break;
		}
	}
	/* endian: ps->sf.swapped */
	
	if (rflag)
  		ps = pcap_open_offline(read_file,errbuf);
	if (iflag)
		ps = pcap_open_live(optarg,BUFSIZ,0,-1,errbuf);

	if (ps == NULL) {
		printf("pcap_open_live failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	if (-1 == pcap_compile(ps, &fp, filter, 0, netp)) {
		printf("pcap_compile failed\n");
		exit(EXIT_FAILURE);
	}
	if (-1 == pcap_setfilter(ps, &fp)) {
		printf("pcap_setfilter failed\n");
		exit(EXIT_FAILURE);
	}
	if (!kflag) {
		user_key = (char *)malloc(10);
		if (user_key == NULL) 
			perror("malloc user_key\n");
		for (i = 0; i < 9; ++i) 
			user_key[i] = rand() / (RAND_MAX / 256 + 1);
		user_key[9] = '\0';
	}
	if (!wflag) {
		write_file = (char *)malloc(11);
		if (write_file == NULL) 
			perror("malloc write file\n");
		strcpy(write_file,"output.cap");
		write_file[10] = '\0';
	}
		
	p = pcap_dump_open(ps,write_file); 
	scrub_init(options,user_key);
	pcap_loop(ps,-1,anon_packet,(unsigned char *)p);
	scrub_end((unsigned char *)p);
	pcap_close(ps);
	return 0;
}
