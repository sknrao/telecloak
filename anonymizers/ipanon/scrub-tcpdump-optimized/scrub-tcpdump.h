
#ifndef _SCRUB_H
#define _SCRUB_H

void scrub_init(char *options, char *user_key);
void anon_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void scrub_end(u_char *user);

#endif
