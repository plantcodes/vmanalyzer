#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
//#include "analyzer.h"

#define LOGFILE "/var/log/tester"

static void * thr_fn(void *arg);

int main(int argc, char *argv[]) {
	/* 
	struct vm_stat *vsp1 = NULL;
	struct smp_stat *ssp1 = NULL;

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
	report_statistic(ssp1, &vsp1);	
	free_memory(&ssp1, &vsp1);
	*/

	/*
	if (daemon(0, 0) == -1) {
		fprintf(stderr, "Error: fail to daemonize the process.");
		perror(strerror(errno));
	}
	openlog(LOGFILE, LOG_PID, LOG_USER);
	syslog(LOG_INFO, "start tester ...\n");
	*/

	pthread_t tid;
	int err;

	err = pthread_create(&tid, NULL, thr_fn, NULL);
	sleep(6);
	printf("Process id: %lu\n", (unsigned long)getpid());
	printf("Main thread id: %lu\n", (unsigned long)pthread_self());

	return 1;
}

static void * thr_fn(void *arg) {
	while (1) {
		printf("Hello\n");
		sleep(2);
	}
}
