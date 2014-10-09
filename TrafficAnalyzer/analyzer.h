#ifndef ANALYZER_H
#define ANALYZER_H


/* struct for VM statistic
   sp_avg = (1-alpha) * sp_avg + alpha * sp
   sp_avg_bias = (1-beta) * sp_avg_bias + beta * (sp-sp_avg)
   sp_wet = sp_avg + k * sp_avg_bias
*/
typedef struct vm_stat {
	char mac[6];		/* mac address of VM */
	long sp;			/* number of sent packets */
	long rp;			/* number of received packets */
	long tp;			/* throughput of VM int time Ts */
	long sp_avg;		/* average number of sent packets */
	long rp_avg;		/* average number of received packets */
	long sp_wet;		/* weighted number of sent packets */
	long rp_wet;		/* weighted number of received packets */
	long sp_avg_bias;	/* average bias of number of sent packets */
	long rp_avg_bias; 	/* average bias of number of received packets */
	float alpha;
	float beta;
	float k;
	struct vm_stat *next;
}vm_stat;

/* Simple statistic information 
 */
struct smp_stat {
	char mac[6];	/* mac address of VM */
	long sp;		/* sent packets */
	long rp;		/* received packets */
	long tp;		/* throughput */
	struct smp_stat *next;
};

/* Get all domain front-end device, namely vifDomID.DevID
 * Get size of VMs list 
 */
int get_all_dev(vm_stat **list, int *size);

/* Create capturing sessions for VMs' front-end device
 * Get a pcap_t array pointer 
 */
int create_capturing(const vm_stat **list, pcap_t *dev, const int size);

/* Set options for capturing 
 */
int set_options(const pcap_t *devs, const int size,  const int snaplen, \
				const int promsic, const int rfmon, const int to_ms, \
				const int buffer_size, const int tstamp_type);

/* Activate all capturing
 */
int activate_capturing(const pcap_t *devs, const int size);


/* Analyze packets and get statistic information
 * 	user	is a pointer to the bytes of smp_stat list header
 */
int analyze_packets(const pcap_t *p, u_char *user);

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
int report_statistic();

#endif
