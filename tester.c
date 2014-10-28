#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include "analyzer.h"

#define LOGFILE "/var/log/tester"

static void * thr_fn(void *arg);
static void exit_hdl(void);

/* global variables */
struct vm_stat *vsp1 = NULL;
struct smp_stat *ssp1 = NULL;

int main(int argc, char *argv[]) {
	
	pthread_t tid;
	int err;
	
	/* detach process */
	if (daemon(0, 1) == -1) {
		fprintf(stderr, "Error: fail to daemonize the process.");
		perror(strerror(errno));
	}
	openlog(LOGFILE, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "start tester ...\n");

	/* emulate a smp_stat list */
	ssp1 = (struct smp_stat *)malloc(sizeof (struct smp_stat));
	if (ssp1 == NULL) {
		fprintf(stderr, "%s:%d Error: fail to allocate memeory for ssp1 ", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	strcpy(ssp1->mac, "012345");
	strcpy(ssp1->vmn, "ux");
	ssp1->rp = 10000;
	ssp1->sp = 20000;
	ssp1->tp = 30000;
	ssp1->next = NULL;
	
	/* create thread to report */
	err = pthread_create(&tid, NULL, thr_fn, NULL);
	/*
	printf("Process id: %lu\n", (unsigned long)getpid());
	printf("Main thread id: %lu\n", (unsigned long)pthread_self());	
	*/
		
	/* emulate statistic */
	while (1) {
		sleep(1);
		ssp1->rp += 1;
		ssp1->sp += 2;
		ssp1->tp += 3;
	}
	
	/* end statistic */
	if (atexit(exit_hdl) != 0) {
		perror("Can not register function.");
	}
	return 1;
}

static void * thr_fn(void *arg) {
	while (1) {
		syslog(Log_INFO, "report statistic.\n");
		report_statistic(&ssp1, &vsp1);
		sleep(6);
	}
}

static void exit_hdl(void) {
	free_memory(&ssp1, &vsp1);
}