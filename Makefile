all: pcap_test

pcap_test: main.o
	gcc -g -o pcap_test main.o -lpcap

main.o: pcap_struct.h main.c
	gcc -g -c -o main.o main.c

clean:
	rm -f pcap_test
	rm -f *.o