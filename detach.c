/* filename: detach.c
 * implementation of functions in detach.h
 */

#include "detach.h"
#include "analyzer.h"

void daemonize(void) {
	if (daemon(0, 1) == -1) {
		fprintf(stderr, "Error: fail to daemonize the process.\n");
		perror(strerror(errno));
	}
}

void get_lock(pthread_mutex_t *lockp) {
	if (pthread_mutex_init(lockp, NULL) != 0) {
		syslog(LOG_ERR, "fail to init a lock.\n");
		exit(EXIT_FAILURE);
	}
}

void free_lock(pthread_mutex_t *lockp) {
	if (pthread_mutex_destroy(lockp) != 0) {
		syslog(LOG_ERR, "fail to free a lock.\n");
		exit(EXIT_FAILURE);
	}
}

void lock_lock(pthread_mutex_t *lockp) {
	if (pthread_mutex_lock(lockp) != 0) {
		syslog(LOG_ERR, "fail to lock a lock.\n");
		exit(EXIT_FAILURE);
	}
}

void unlock_lock(pthread_mutex_t *lockp) {
	if (pthread_mutex_unlock(lockp) != 0) {
		syslog(LOG_ERR, "fail to unlock a lock.\n");
		exit(EXIT_FAILURE);
	}
}

void * thr_fn(void *arg) {
	struct smp_stat *tmp = NULL;
	while (1) {
		/* lock_lock(&lock); there is a lock in report_statistic */
		report_statistic(ssp, &vsp);
		tmp = ssp;
		while (tmp != NULL) {
			tmp->rp = 0;
			tmp->sp = 0;
			tmp->tp = 0;
			tmp = tmp->next;
		}
		/* unlock_lock(&lock); */
		syslog(LOG_INFO, "reported statistic.\n"); 
		sleep(10);
	}
}

void create_thread(pthread_t *tidp, void *(*thr_fn)(void *)) {
	int errno;
	errno = pthread_create(tidp, NULL, thr_fn, NULL);
		
	switch(errno) {
	case 0:
		break;
	case EAGAIN:
		syslog(LOG_ERR, "%s\n", "Insuffient resource to create thread, or the number of thread exceed the limitation.");
		exit(EXIT_FAILURE);
	case EINVAL:	
		syslog(LOG_ERR, "%s\n", "Invalid settings in pthread_attr_t.");
		exit(EXIT_FAILURE);
	case EPERM:
		syslog(LOG_ERR, "%s\n", "Permisson denied.");
		exit(EXIT_FAILURE);
	}
}

void sig_int(int signo) {
	syslog(LOG_INFO, "exit from SIGINT, close pcap_t , close log, free lock and free memory before exit\n");
	pcap_close(dev);
	free_memory(&ssp, &vsp);
	closelog();
	free_lock(&lock);
}

void sig_term(int signo) {
	syslog(LOG_INFO, "exit from SIGTERM, close pcap_t , close log, free lock and free memory before exit\n");
	pcap_close(dev);
	free_memory(&ssp, &vsp);
	closelog();
	free_lock(&lock);
}

void sig_tstp(int signo) {
	syslog(LOG_INFO, "exit from SIGTSTP, close pcap_t, close log, free lock and free memory before exit\n");
	pcap_close(dev);
	free_memory(&ssp, &vsp);
	closelog();
	free_lock(&lock);
}

void install_sighdl(int signo, void (* sighdl)(int)) {
	struct sigaction act, oact;
	char buf[10] = "";

	switch (signo) {
	case SIGINT:
		sprintf(buf, "SIGINT");
		break;
	case SIGTERM:
		sprintf(buf, "SIGTERM");
		break;
	case SIGTSTP:
		sprintf(buf, "SIGTSTP");
		break;
	}

	act.sa_handler = sighdl;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(signo, &act, &oact) < 0) {
		syslog(LOG_ERR, "Error: fail to install handler of %s.\n", buf);
		exit(EXIT_FAILURE);
	}
}
