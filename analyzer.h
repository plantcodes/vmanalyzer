/* filename: analyzer.h
 * declears:
 * data structs about VM network statistical characters, 
 * functions about statistic operations
 */

#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>

/* ************************************************************
 * ********************** Macros ******************************
 * ************************************************************
 */

/* macros for vm_stat iteratoin
 * see comments of `struct vm_stat`
 */
#define MAX_NAME_LEN 256	/* max VM name length */
#define MAX_JSON_LEN 4096	/* max length of JSON structure of report */
#define ALPHA 0.5			/* parameters of the iteration formula */
#define BETA 0.5
#define K 0.5
#define TS 300				/* report period: 300s(5min) */

/* macros:
 * transfer hexadecimal to decimal
 * transfer two hexadecimal number to 8-bit value
 */
#define H2D(c) (((c) <= '9') ? ((c)-'0') : ((c)-'a'+10))
#define S2C(s) (H2D(*(s))*16 + H2D(*(s+1)))

/* ***********************************************************
 * ************* Defination of data structure ****************
 * ***********************************************************
 */

/* struct for VM statistic
   sp_avg 		= ((1-ALPHA)*sp_avg) + (ALPHA*sp)
   sp_avg_bias	= ((1-BETA)*sp_avg_bias) + (BETA*(sp-sp_avg))
   sp_wet		= (sp_avg) + (K*sp_avg_bias)
*/
struct vm_stat {
	char vmn[MAX_NAME_LEN];	/* VM name */
	long sp;				/* number of sent packets */
	long rp;				/* number of received packets */
	long tp;				/* throughput of VM int time Ts */
	long sp_avg;			/* average number of sent packets */
	long rp_avg;			/* average number of received packets */
	long sp_avg_bias;		/* average bias of number of sent packets */
	long rp_avg_bias; 		/* average bias of number of received packets */
	long sp_wtd;			/* weighted number of sent packets */
	long rp_wtd;			/* weighted number of received packets */
	struct vm_stat *next;
};

/* Simple statistic information 
 */
struct smp_stat {
	char mac[6];			/* mac address of VM */
	char vmn[MAX_NAME_LEN]; /* VM name */
	long sp;				/* sent packets */
	long rp;				/* received packets */
	long tp;				/* throughput */
	struct smp_stat *next;
};

/* *************************************************************
 * *************** Declaration of global variable **************
 * *************************************************************
 */

struct smp_stat *ssp;	/* mac address list, filled by read_mac_list() and analyze_packets() */
struct vm_stat *vsp;	/* statistic list, filled by report_statistic() */
pcap_t *dev;			/* pcap_t pointer, filled by create_capturing() */
pthread_mutex_t lock;	/* a lock to read/write smp_stat list(mac address list) */

/* *************************************************************
 * ************* Declaration of external functions *************
 * *************************************************************
 */

/* Read mac addresses list from file: /var/vmstd/mac.list
 */
extern void read_mac_lst(struct smp_stat **listp);

/* Get an pcap capture handle
 * save pcap_t * in *devp
 */
extern void create_capturing(pcap_t **devp, char *dev_name, char *errbuf);

/* Set options for capturing 
 */
extern void set_options(pcap_t *dev,  const int snaplen, \
				const int promisc, const int rfmon, const int to_ms, \
				const int buffer_size, const int tstamp_type);

/* Activate all capturing
 */
extern void activate_capturing(pcap_t *dev, char *dev_name);

/* compile a bpf filter program, 
 * set the filter for the capturing
 * dev: pcap_t pointer of device
 * prgmp: pointer of bpf filter program, to store compiled program
 * exp: expression of fileter
 * netmask: 
 */
extern void set_filter(pcap_t *dev, struct bpf_program *prgmp, char *exp, bpf_u_int32 netmask); 

/* Analyze packets and get statistic information
 * 	user	is a pointer to the bytes of smp_stat list header
 * 	return value:
 * 	 0, cnt is exhausted
 *	-1, error occurs
 *	-2, pcap_breakloop() called
 */
extern void analyze_packets(pcap_t *p, u_char *user);

/* pcap_handler
 * if the packet is send to/from one of the VMs, then do statistics
 * 	user	is a pointer to the bytes of smp_stat list header
 * 			(struct smp_stat *)user
 *	h	 	is the packet(pkt) header(hdr) of this packet
 * 	bytes	is the first caplen bytes of data in this packet
 */
extern void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/* Report VM traffic statistic information to file:
 */
extern void report_statistic(struct smp_stat *ssl, struct vm_stat **vslp);

/* Release dynamic memeory
 * 
 */
extern void free_memory(struct smp_stat **sslp, struct vm_stat **vslp);

#endif
