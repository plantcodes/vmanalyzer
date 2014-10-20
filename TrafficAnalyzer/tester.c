#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "analyzer.h"

static void * thr_fn(void *);

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
	pthread_t tid;
	int err;

	err = pthread_create(&tid, NULL, thr_fn, NULL);
	printf("Process id: %lu", get_pid());
	printf("Main thread id: %lu", pthread_self());

	return 1;
}

static void * thr_fn(void *) {
	printf("Hello\n");
	while (1) {
		sleep(100);
	}
}
