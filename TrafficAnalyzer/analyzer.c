#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "analyzer.h"

int get_all_dev(vm_stat **list, int *size) {
	pcap_if_t **alldevs = NULL;
	vm_stat *vmp = NULL, *vmp_prev = NULL;
	pcap_if_t *devp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	int first = 1;

	ret = pcap_findalldevs(alldevs, errbuf);
	if (ret == -1) {
		fprintf(stderr, "Error:%s\n", errbuf);
		exit(EXIT_FAILURE);
	} else if (ret == 0) {
		if (alldevs != NULL) {			/* find some devices */
			devp = *alldevs;
			while (devp != NULL) {		/* find all devices preceded with vif */
				if (strncmp(devp->name, "vif", 3) == 0) {
					
					vmp= (vm_stat *)malloc(sizeof (vm_stat));	/* add a new node in VMs list */
					if (vmp == NULL) {
						fprintf(stderr, "Error: malloc failed !\n");
						exit(EXIT_FAILURE);
					}
					*size ++;
					vmp->next = NULL;
					vmp->dev_name = devp->name;
					if (vmp_prev != NULL) {
						vmp_prev->next = vmp;
					}
					vmp_prev = vmp;
					if (first == 1) {		/* first node of VMs list */
						list = &vmp;
						first = 0;
					}
				}
			}
		}
	}
	return 0;  /* get no empty VMs list */
}

int create_capturing(const vm_stat **list, pcap_t **devs, const int size) {
	char errbuf[PCAP_ERRBUF_SIZE];
	vm_stat *vmp;
	int i = 0;

	devs = (pcap_t **)malloc(sizeof (pcap_t *) * size);	/* allocate memory for pcap_t pointers returned by pcap_create */
	if (devs == NULL) {
		fprintf(stderr, "Error: malloc failed !\n");
		exit(EXIT_FAILURE);
	}

	vmp = *list;
	while (vmp != NULL) {					/* create capturing session for all vif devices */
		*(devs+i) = pcap_create(vmp->dev_name, errbuf);	/* save pointer */
		if (*(devs+i) == NULL) {			/* pcap_create failed */
			fprintf(stderr, "Error: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
		i ++;
		vmp = vmp->next;
	}
	return 0;	/* create capturing session successfully */
}

int set_options(const pcap_t *devs, const int size,  const int snaplen, const int promsic, const int rfmon, const int to_ms, const int buffer_size, const int tstamp_type) {
	int ret;
	int i;
	for (i = 0; i < size; i ++) {
		ret = pcap_set_snaplen(devs+i, snaplen);            	/* return 0, PCAP_ERROR_ACTIVATED */
		if (ret == PCAP_ERROR_ACTIVATED ) {
			fprintf(stderr, "Error: PCAP_ERROR_ACTIVATED !");
			break;
		}
		ret = pcap_set_promisc(dev+i, promisc);
		ret = pcap_set_rfmon(dev+i, rfmon);
		ret = pcap_set_timeout(dev+i, to_ms);
		ret = pcap_set_buffer_size(dev+i, buffer_size);
		ret = pcap_set_tstamp_type(dev+i, tstamp_type);
	}
	return ret;	
}

int activate_capturing(const pcap_t *dev, const int size) {
	int ret;
	int i;
	for (i = 0; i < size; i ++) {
		ret = pcap_activate(dev+i);
		switch (ret) {
		case 0 :
			fprintf(stderr, "Activated a sniffer session for device %s!\n", dev_name);
			break;
		case PCAP_WARNING_PROMISC_NOTSUP :
			fprintf(stderr, "Waring: promiscuous mode not supported !\n");
			break;
		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP :
			fprintf(stderr, "Waring: time stamp type not supported !\n");
			break;
		case PCAP_WARNING :
			fprintf(stderr, "Waring: other waring !\n");
			break;
		case PCAP_ERROR_ACTIVATED :
			fprintf(stderr, "Error: device already activated !\n");
			exit(EXIT_FAILURE);
		case PCAP_ERROR_NO_SUCH_DEVICE :
			fprintf(stderr, "Error: no such device !\n");
			exit(EXIT_FAILURE);
		case PCAP_ERROR_PROMISC_PERM_DENIED :
			fprintf(stderr, "Error: permission denied !\n");
			exit(EXIT_FAILURE);
		case PCAP_ERROR_RFMON_NOTSUP :
			fprintf(stderr, "Error: monitor mode not support !\n");
			exit(EXIT_FAILURE);
		case PCAP_ERROR :
			fprintf(stderr, "Error: other error !\n");
			exit(EXIT_FAILURE);
		}
	}
	
	return ret;
}

int analyze_packets(const pcap_t *p, u_char *user) {
	pcap_loop(p, -1, packet_handler, user);	/* process packets infinitely until call pcap_breakloop */
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	struct ether_header *ehp = NULL;	/* ethernet header pointer */
	struct smp_stat *sslst = NULL;		/* simple statistic list */
	struct smp_stat *hit = NULL;		/* the item hits the src or dst mac addr */
	u_char * ptr = NULL;				/* byte pointer */

	sslst = (struct smp_stat *)user;
	ehp = (struct ether_header *)bytes;	/* ethernet header, net/ethernet.h */
	ptr = ehp->ether_shost;				/* source ethernet address */
	if (is_in(ptr, sslst, &hit) == 0) {	/* a packet send from VM */
		hit->sp ++;
		tp += h->len;
	}

	ptr = ehp->ether_dhost;				/* destination ethernet address */
	if (is_in(ptr, sslst, &hit) == 0) {	/* a packet send to VM */
		hit->rp ++;
		tp += h->len;
	}
}

int is_in(const u_char *mac, const struct smp_stat *list, struct smp_stat **hitp) {
	struct smp_stat *ssp;	/* smp_stat pointer */
	ssp = list;
	while (ssp->next != NULL) {
		if (memcmp(mac, ssp->mac) == 0) {
			*hitp = ssp;	/* save the item hits the mac */
			return 0;	/* the mac addres is in the list */
		}
	}
	return 1;			/* the mac address not in the list */
}
int report_statistic() {

}
