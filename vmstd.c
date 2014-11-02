/* filename: vmstd.c
 * a daemon process, do VM network statistic
 * dynamic heap memory: 
 * 		mac address list
 *		VM statistic list
 */

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "analyzer.h"
#include "detach.h"

/* declare global variables */
extern struct smp_stat *ssp;
extern struct vm_stat *vsp;
extern pcap_t *dev;
extern pthread_mutex_t lock;

int main(int argc, char *argv[])
{
	/* local variables */
	char dev_name[] = "xenbr0";				/* NIC device name */
	char errbuf[PCAP_ERRBUF_SIZE];			/* buffer for error messages */
	int ret = 0;							/* return value */
	int snaplen = 84;						/* ethernet header and ip header, 34 */
	int promisc = 1;						/* non zero */
	int rfmon = 0;							/* zero, do not set monitor mode */
	int to_ms = 1000;						/* milliseconds for read time out */
	int buffer_size = 10485760;				/* buffer size is 10MB */
	int tstamp_type = PCAP_TSTAMP_HOST;		/* time stamp type, provided by network adapter */
	struct bpf_program prgm;				/* filter program */
	bpf_u_int32 netmask = 0x00000000;		/* any address */
	pthread_t tid;							/* thread id */
											/* filter expressoin */
	char exp[] = "ether host 00:16:3e:db:e6:38 or 00:16:3e:9d:b1:ee";

	ssp = NULL;
	vsp = NULL;
	dev = NULL;

	/* Detaches itself from teminal and run in background */
	/*
	daemonize();
	openlog(NULL, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "start vmstd.\n");
	*/
	openlog(NULL, LOG_PID, LOG_USER);
	
	/* Install signal handler for SIGINT, SIGTERM */
	install_sighdl(SIGINT, sig_int);
	install_sighdl(SIGTERM, sig_term);
	install_sighdl(SIGTSTP, sig_tstp);
	syslog(LOG_INFO, "installed sighanler for SIGINT, SIGTERM, SIGTSTP.\n");

	/* Read mac addres file from /var/vmstd/mac.list */
	read_mac_lst(&ssp);
	syslog(LOG_INFO, "readed mac address list.\n");

	/* Create an capturing */
	create_capturing(&dev, dev_name, errbuf);
	syslog(LOG_INFO, "created capturing.\n");

	/* Options for capturing */
	set_options(dev, snaplen, promisc, rfmon, to_ms, buffer_size, tstamp_type);
	syslog(LOG_INFO, "set options.\n");


	/* Activates a sniffer session for */
	activate_capturing(dev, dev_name);
	syslog(LOG_INFO, "activated capturing.\n");

	/* Sets filters if needed */
	set_filter(dev, &prgm, exp, netmask);
	syslog(LOG_INFO, "set filter.\n");

	/* Get a lock to r/w ssp list */
	get_lock(&lock);
	syslog(LOG_INFO, "get a lock.\n");

	/* Create a thread to report VM statistic information periodically 
	 * see /var/vmstd/report.json */
	create_thread(&tid, thr_fn);
	syslog(LOG_INFO, "Create a new thread to report statistic.\n");

	/* Analyze packets */
	syslog(LOG_INFO, "start to analyze packets.\n");
	analyze_packets(dev, (u_char *)ssp);

	return (0);
}
