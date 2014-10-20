#include <pcap/pcap.h>

#ifndef ANALYZER_H
#define ANALYZER_H

#define MAX_NAME_LEN 256
#define MAX_JSON_LEN 4096
#define ALPHA 0.5
#define BETA 0.5
#define K 0.5

#define H2D(c) (((c) <= '9') ? ((c)-'0') : ((c)-'a'+10))
#define S2C(s) (H2D(*(s))*16 + H2D(*(s+1)))

/* struct for VM statistic
   sp_avg = (1-alpha) * sp_avg + alpha * sp
   sp_avg_bias = (1-beta) * sp_avg_bias + beta * (sp-sp_avg)
   sp_wet = sp_avg + k * sp_avg_bias
*/
typedef struct vm_stat {
	char vmn[MAX_NAME_LEN];		/* VM name */
	long sp;			/* number of sent packets */
	long rp;			/* number of received packets */
	long tp;			/* throughput of VM int time Ts */
	long sp_avg;		/* average number of sent packets */
	long rp_avg;		/* average number of received packets */
	long sp_avg_bias;	/* average bias of number of sent packets */
	long rp_avg_bias; 	/* average bias of number of received packets */
	long sp_wtd;		/* weighted number of sent packets */
	long rp_wtd;		/* weighted number of received packets */
	struct vm_stat *next;
}vm_stat;

/* Simple statistic information 
 */
struct smp_stat {
	char mac[6];	/* mac address of VM */
	char vmn[MAX_NAME_LEN];
	long sp;		/* sent packets */
	long rp;		/* received packets */
	long tp;		/* throughput */
	struct smp_stat *next;
};

/* Read mac addresses list from file: mac.lst
 */
void read_mac_lst(struct smp_stat **listp);

/* Set options for capturing 
 */
void set_options(pcap_t *dev,  const int snaplen, \
				const int promisc, const int rfmon, const int to_ms, \
				const int buffer_size, const int tstamp_type);

/* Activate all capturing
 */
void activate_capturing(pcap_t *dev, char *dev_name);


/* Analyze packets and get statistic information
 * 	user	is a pointer to the bytes of smp_stat list header
 * Return value:
 * 	 0, cnt is exhausted
 *	-1, error occurs
 *	-2, pcap_breakloop() called
 */
int analyze_packets(pcap_t *p, u_char *user);

/* pcap_handler
 * if the packet is send to/from one of the VMs, then do statistics
 * 	user	is a pointer to the bytes of smp_stat list header
 * 			(struct smp_stat *)user
 *	h	 	is the packet(pkt) header(hdr) of this packet
 * 	bytes	is the first caplen bytes of data in this packet
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/* Report VM traffic statistic information to file:
 */
void report_statistic(struct smp_stat *ssl, struct vm_stat **vslp);

/* Release dynamic memeory
 * 
 */
void free_memory(struct smp_stat **sslp, struct vm_stat **vslp);

#endif
