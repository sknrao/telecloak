scrub-tcpdump: standalone.o scrub-tcpdump.o checksum.o
	gcc md5.c standalone.o scrub-tcpdump.o checksum.o -g -o $@ -lpcap

checksum.o: checksum.c
	gcc -g -c -I. -o $@ $<

scrub-tcpdump.o: scrub-tcpdump.c
	gcc -Wall -g -c -I. -o $@ $<

standalone.o: standalone.c
	gcc -g -c -I. -o $@ $<

clean:
	$(RM) *.o scrub-tcpdump
