#include <stdio.h>
#include <pcap/pcap.h>
#include <glib.h>
#include <unistd.h>
#include "analyzer.h"

int main(int argc, char *argv[])
{
	pcap_t * dev;
	char dev_name[] = "xenbr0";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_stat ps;
	int snaplen;
	int promisc;
	int rfmon;
	int to_ms;
	int buffer_size;
	int tstamp_type;

	/* Detaches itself from teminal and run in background
	*/

	/* Looks up all device of vifDOMID.DEVID
	   And creates a list for a VM(guest domain) statistic
	*/


	/* Creates a sniffer seesion for network device
	*/

	/* Options for capturing
	 */

	/* Activates a sniffer session for 
	 */

	/* Sets filters if needed
	*/

	/* Reads packets, and get packet length
	*/

	/* Gets capture statistics, numbers
	*/
	ret = pcap_stats(dev, &ps);
	if (ret == -1) {
		pcap_perror(dev, "Error:");	
	} else if (ret == 0) {
		printf("Number of recieved packects: %d\n", ps.ps_recev);
		printf("Number of packects dropped for insufficient buffer %d\n", ps.ps_drop);
		printf("Number of packects dropped by network interface: %d\n", ps.ps_ifdrop);
	}






	return (0);
}
