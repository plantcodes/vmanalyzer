/* filename: vmstd.c
 * a daemon process, do VM network statistic
 * dynamic heap memory: 
 * 		mac address list
 *		VM statistic list
 */

#include <stdlib.h>
#include <unistd.h>
#include "analyzer.h"

int main(int argc, char *argv[])
{
	pcap_t * dev = NULL;
	char dev_name[] = "xenbr0";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	int snaplen = 84;						/* ethernet header and ip header, 34 */
	int promisc = 1;						/* non zero */
	int rfmon = 0;							/* zero, do not set monitor mode */
	int to_ms = 1000;							/* milliseconds for read time out */
	int buffer_size = 1048576;				/* buffer size is 1MB */
	int tstamp_type = PCAP_TSTAMP_HOST;		/* time stamp type, provided by network adapter */
	struct bpf_program prgm;				/* filter program */
	bpf_u_int32 netmask = 0x00000000;		/* any address */
	struct smp_stat *mlst = NULL;			/* mac address list */
	struct vm_stat *slst = NULL;			/* statistic list */
	char exp[] = "ether dst 00:16:3e:07:b2:80";

	/* Detaches itself from teminal and run in background */

	/* Read mac addres file from /var/vmstd/mac.lst */
	read_mac_lst(&mlst);

	/* Get a live capture handle */
	dev = pcap_create(dev_name, errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* Options for capturing */
	set_options(dev, snaplen, promisc, rfmon, to_ms, buffer_size, tstamp_type);


	/* Activates a sniffer session for */
	activate_capturing(dev, dev_name);

	/* Sets filters if needed */
	ret = pcap_compile(dev, &prgm, exp, 1, netmask);
	if (ret == -1) {
		pcap_perror(dev, "Error: ");
		exit(EXIT_FAILURE);
	}
	ret = pcap_setfilter(dev, &prgm);
	if (ret == -1) {
		pcap_perror(dev, "Error: ");
		exit(EXIT_FAILURE);
	}

	/* Reads packets infinitly, and get packet length */
	/*
	ret = analyze_packets(dev, (u_char *)mlst);
	switch (ret) {
	case 0:
		break;
	case -1:
		pcap_perror(dev, "Error: ");
		exit(EXIT_FAILURE);
		break;
	case -2:
		fprintf(stderr, "Info: pcap_breakloop() is called.\n");
		break;
	}
	*/

	/* Only for test */
	const u_char *bytes = NULL;
	struct pcap_pkthdr h;
	while ((bytes=pcap_next(dev, &h)) != NULL) {
		packet_handler((u_char *)mlst, &h, bytes);
	}

	/* analyze packets stopped, then close pcap_t, free heap memory
	 */

	/* Close pcap_t */
	pcap_close(dev);

	/* Free memory */
	free_memory(&mlst, &slst);

	return (0);
}
