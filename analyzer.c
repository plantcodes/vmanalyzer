/* filename: analyzer.c
 * implementation of function decleared in analyzer.h
 * declaratoin and implementation of local function
 */

#include "analyzer.h"

/* *******************************************************
 * ********* Declaration of local(inner) methods *********
 * *******************************************************
 */

/* Inner method
 * get mac address and VM name from a line of mac.lst
 */
static void parse_line(const char *s, char *mac, char *vmn);

/* Inner method
 */
static int s2c(char *s);

/* Inner method
 * hexadecimal to decimal
 * c <= '9' ? c-'0' : c-'a'+10
 */
static int h2d(char c);

/* Inner method
 * return 0, the mac address is in the smp_stat list 
 */
static int is_in(const u_char *mac, struct smp_stat *list, struct smp_stat **hitp);

/* Inner method * Find a VM by name, if it is not exist, then add a new node to the list
 * If empty list, them modify vm_stat list header(vslp)
 * Never return NULL
 */
static struct vm_stat * find_vm(const char *name, struct vm_stat **vslp);

/* Inner method
 * Using current smp_stat imformation, it makes a deeper statistic
 * Assume that a VM may have more than one Network Interface Card 
 */
static void make_statistic(const struct smp_stat *ssl, struct vm_stat **vslp);


/* **************************************************************
 * ********* Implementation of global and local methods *********
 * **************************************************************
 */

static void parse_line(const char *s, char *mac, char *vmn) {
	const char *p = s;
	int i = 0;

	/* get mac address */
	do {
		mac[i] = S2C(p);	
		p += 3;
		i ++;
	} while (*(p-1) != ' ');

	/* get VM name */
	strncpy(vmn, p, strlen(p)-1);
}

static int s2c(char *s) {
	return (H2D(*(s))*16 + H2D(*(s+1)));
}

static int h2d(char c) {
	if (c <= '9')	
		return (c-'0');
	else
		return (c-'a'+10);
}

void read_mac_lst(struct smp_stat **lstp) {
	char path[] = "/var/vmstd/mac.list";
	char buf[280] = "";
	struct smp_stat *tmp;
	struct smp_stat *pre;
	FILE *fp = fopen(path, "r");

	if (fp == NULL) {
		syslog(LOG_ERR, "Error: fail to open file %s\n %s", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fgets(buf, 280, fp);
	tmp = (struct smp_stat *)malloc(sizeof (struct smp_stat));
	memset(tmp->mac, 0, MAX_NAME_LEN);
	parse_line(buf, tmp->mac, tmp->vmn);
	tmp->sp = 0;
	tmp->rp = 0;
	tmp->tp = 0;
	tmp->next = NULL;
	*lstp = tmp;	/* set mac list header */
	pre = tmp;
	memset(buf, 0, 280);
	while (fgets(buf, 280, fp) != NULL) {
		tmp = (struct smp_stat *)malloc(sizeof (struct smp_stat));
		memset(tmp->mac, 0, MAX_NAME_LEN);
		parse_line(buf, tmp->mac, tmp->vmn);
		tmp->sp = 0;
		tmp->rp = 0;
		tmp->tp = 0;
		tmp->next = NULL;
		pre->next = tmp;
		pre = tmp;
		memset(buf, 0, 280);
	}
	fclose(fp);
}

void create_capturing(pcap_t **devp, char *dev_name, char *errbuf) {
	*devp = pcap_create(dev_name, errbuf);
	if (*devp == NULL) {
		syslog(LOG_ERR, "%s\n", errbuf);
		exit(EXIT_FAILURE);
	}
}

void set_options(pcap_t *dev,  const int snaplen, \
						const int promisc, const int rfmon, \
						const int to_ms, const int buffer_size, \
						const int tstamp_type) {
	int ret;
	ret = pcap_set_snaplen(dev, snaplen);            
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	}
	ret = pcap_set_promisc(dev, promisc);
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	}
	ret = pcap_set_rfmon(dev, rfmon);
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	}
	ret = pcap_set_timeout(dev, to_ms);
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	}
	ret = pcap_set_buffer_size(dev, buffer_size);
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	}
	ret = pcap_set_tstamp_type(dev, tstamp_type);
	if (ret == PCAP_ERROR_ACTIVATED ) {
		syslog(LOG_ERR, "%s\n", "Error: PCAP_ERROR_ACTIVATED !");
		exit(EXIT_FAILURE);
	} else if (ret == PCAP_ERROR_CANTSET_TSTAMP_TYPE) {
		syslog(LOG_ERR, "%s\n", "Error: time stamp type not supported");
		exit(EXIT_FAILURE);
	}
}

void activate_capturing(pcap_t *dev, char *dev_name) {
	int ret;
	ret = pcap_activate(dev);
	switch (ret) {
	case 0 :
		syslog(LOG_ERR, "Activated a sniffer session for device %s!\n", dev_name);
		break;
	case PCAP_WARNING_PROMISC_NOTSUP :
		syslog(LOG_ERR, "Waring: promiscuous mode not supported !\n");
		break;
	case PCAP_WARNING_TSTAMP_TYPE_NOTSUP :
		syslog(LOG_ERR, "Waring: time stamp type not supported !\n");
		break;
	case PCAP_WARNING :
		syslog(LOG_ERR, "Waring: other waring !\n");
		break;
	case PCAP_ERROR_ACTIVATED :
		syslog(LOG_ERR, "Error: device already activated !\n");
		exit(EXIT_FAILURE);
	case PCAP_ERROR_NO_SUCH_DEVICE :
		syslog(LOG_ERR, "Error: no such device !\n");
		exit(EXIT_FAILURE);
	case PCAP_ERROR_PROMISC_PERM_DENIED :
		syslog(LOG_ERR, "Error: permission denied !\n");
		exit(EXIT_FAILURE);
	case PCAP_ERROR_RFMON_NOTSUP :
		syslog(LOG_ERR, "Error: monitor mode not support !\n");
		exit(EXIT_FAILURE);
	case PCAP_ERROR :
		syslog(LOG_ERR, "Error: other error !\n");
		exit(EXIT_FAILURE);
	}
}

void set_filter(pcap_t *dev, struct bpf_program *prgmp, char *exp, bpf_u_int32 netmask) {
	int ret;
	ret = pcap_compile(dev, prgmp, exp, 1, netmask);
	if (ret == -1) {
		syslog(LOG_ERR, "%s\n", pcap_geterr(dev));
		exit(EXIT_FAILURE);
	}
	ret = pcap_setfilter(dev, prgmp);
	if (ret == -1) {
		syslog(LOG_ERR, "%s\n", pcap_geterr(dev));
		exit(EXIT_FAILURE);
	}
}

static int is_in(const u_char *mac, struct smp_stat *list, struct smp_stat **hitp) {
	struct smp_stat *ssp;	/* smp_stat pointer */
	ssp = list;
	while (ssp != NULL) {
		if (memcmp(mac, ssp->mac, 6) == 0) {
			*hitp = ssp;	/* save the item hits the mac */
			return 0;		/* the mac addres is in the list */
		}
		ssp = ssp->next;
	}
	return 1;				/* the mac address not in the list */
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	const struct ether_header *ehp = NULL;	/* ethernet header pointer */
	struct smp_stat *sslst = NULL;			/* simple statistic list */
	struct smp_stat *hit = NULL;			/* the item hits the src or dst mac addr */
	const u_char * ptr = NULL;				/* byte pointer */

	sslst = (struct smp_stat *)user;
	ehp = (struct ether_header *)bytes;	/* ethernet header, net/ethernet.h */
	ptr = ehp->ether_shost;				/* source ethernet address */
	lock_lock(&lock);
	if (is_in(ptr, sslst, &hit) == 0) {	/* a packet send from VM */
		hit->sp ++;
		hit->tp += h->len;
	}

	ptr = ehp->ether_dhost;				/* destination ethernet address */
	if (is_in(ptr, sslst, &hit) == 0) {	/* a packet send to VM */
		hit->rp ++;
		hit->tp += h->len;
	}
	unlock_lock(&lock);
}

void analyze_packets(pcap_t *p, u_char *user) {
	int ret;

	ret = pcap_loop(p, -1, packet_handler, user);	/* process packets infinitely until call pcap_breakloop */
	switch (ret) {
	case 0:
		syslog(LOG_INFO, "Info: pcap_loop ended.\n");
		break;
	case -1:
		syslog(LOG_ERR, "%s\n", pcap_geterr(p));
		exit(EXIT_FAILURE);
		break;
	case -2:
		syslog(LOG_INFO, "Info: pcap_breakloop() is called.\n");
		break;
	}
}

static struct vm_stat * find_vm(const char *name, struct vm_stat **vslp) {
	struct vm_stat *vsp = *vslp;
	struct vm_stat *vsp_prev = vsp;
	while (vsp != NULL) {
		if (strcmp(name, vsp->vmn) == 0) {
			return vsp;
		}
		vsp_prev = vsp;
		vsp = vsp->next;
	}

	/* vm_stat list empty or no item found */
	vsp = (struct vm_stat *)malloc(sizeof (struct vm_stat));
	if (vsp == NULL) {
		syslog(LOG_ERR, "Error: malloc failed!\n");
		exit(EXIT_FAILURE);
	}
	strcpy(vsp->vmn, name);		/* initialize new node */
	vsp->sp = 0;
	vsp->rp = 0;
	vsp->tp = 0;
	vsp->sp_avg = 0;
	vsp->rp_avg = 0;
	vsp->sp_wtd = 0;
	vsp->rp_wtd = 0;
	vsp->sp_avg_bias = 0;
	vsp->rp_avg_bias = 0;
	vsp->next = NULL;

	if (*vslp == NULL) {		/* list empty, modify list header */
		*vslp = vsp;
		return vsp;
	}
	vsp_prev->next = vsp;		/* list not empty and no item found, add new idterm */
	return vsp;
}

static void make_statistic(const struct smp_stat *ssl, struct vm_stat **vslp) {
	const struct smp_stat *ssp = ssl;	/* smp_stat pointer */
	struct vm_stat *vsp = NULL;			/* vm_stat pointer */

	/* traverse smp_stat list and get all VM statistic information */
	lock_lock(&lock);
	while (ssp != NULL) {	
		vsp = find_vm(ssp->vmn, vslp);	/* find vm_stat iterm */
		vsp->sp = ssp->sp;
		vsp->rp = ssp->rp;
		vsp->tp = ssp->tp;
		ssp = ssp->next;
	}
	unlock_lock(&lock);

	/* Traverse all VM in vm_stat list and count all stat variable */
	vsp = *vslp;
	while (vsp != NULL) {
		vsp->sp_avg = (1-ALPHA) * (vsp->sp_avg) + ALPHA * (vsp->sp);
		vsp->rp_avg = (1-ALPHA) * (vsp->rp_avg) + ALPHA * (vsp->rp);
		vsp->sp_avg_bias = (1-BETA) * (vsp->sp_avg_bias) + BETA * (vsp->sp_avg);
		vsp->rp_avg_bias = (1-BETA) * (vsp->rp_avg_bias) + BETA * (vsp->rp_avg);
		vsp->sp_wtd = (vsp->sp_avg) + K * (vsp->sp_avg_bias); 
		vsp->rp_wtd = (vsp->rp_avg) + K * (vsp->rp_avg_bias); 
		vsp = vsp->next;
	}
}

void report_statistic(struct smp_stat *ssl, struct vm_stat **vslp) {
	char path[] = "/var/vmstd/report.json";	
	FILE *fp = fopen(path, "w+");
	int ret;
	char buf[MAX_JSON_LEN] = "";
	struct vm_stat *vsp = NULL;

	if (fp == NULL) {
		syslog(LOG_ERR, "Error: failed to open file %s .\n%s", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	make_statistic(ssl, vslp);
	vsp = *vslp;
	while (vsp != NULL) {
		sprintf(buf, "{");
		sprintf(&buf[strlen(buf)], "\"vmName\":\"%s\", ", vsp->vmn);
		sprintf(&buf[strlen(buf)], "\"sentPackets\":%ld, ", vsp->sp);
		sprintf(&buf[strlen(buf)], "\"receivedPackets\":%ld, ", vsp->rp);
		sprintf(&buf[strlen(buf)], "\"throughPut\":%ld, ", vsp->tp);
		sprintf(&buf[strlen(buf)], "\"averageSendPackets\":%ld, ", vsp->sp_avg);
		sprintf(&buf[strlen(buf)], "\"averageReceivedPackets\":%ld, ", vsp->rp_avg);
		sprintf(&buf[strlen(buf)], "\"biasAverageSentPackets\":%ld, ", vsp->sp_avg_bias);
		sprintf(&buf[strlen(buf)], "\"biasAverageReceivedPackets\":%ld, ", vsp->rp_avg_bias);
		sprintf(&buf[strlen(buf)], "\"weightedSendPackets\":%ld, ", vsp->sp_wtd);
		sprintf(&buf[strlen(buf)], "\"weightedReceivedPackets\":%ld", vsp->rp_wtd);
		sprintf(&buf[strlen(buf)], "}\n");
		ret = fputs(buf, fp);
		memset(buf, 0, MAX_JSON_LEN);
		vsp = vsp->next;
	}
	fclose(fp);
}
void free_memory(struct smp_stat **sslp, struct vm_stat **vslp) {
	struct smp_stat *ssp, *sslh;	/* smp_stat pointer and smp_stat list header */
	struct vm_stat *vsp, *vslh;		/* vm_stat pointer and vm_stat list header */

	sslh = *sslp;
	while (sslh != NULL) {
		ssp = sslh;
		sslh = sslh->next;
		free(ssp);
	}
	*sslp = NULL;

	vslh = *vslp;
	while (vslh != NULL) {
		vsp = vslh;
		vslh = vslh->next;
		free(vsp);
	}
	*vslp = NULL;
}
