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

void already_running(void) {
	int fd;
	char buf[16] = "";

	/* open lock file */
	fd = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0) {
		syslog(LOG_ERR, "can not open %s: %s\n", LOCKFILE, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* try add a record lock to lockfile */
	if (lockf(fd, F_TLOCK, 0) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			syslog(LOG_ERR, "can not lock file %s, a copy of the daemon process is already running.\n", LOCKFILE);
			close(fd);
			exit(EXIT_FAILURE);
		} else {
			syslog(LOG_ERR, "can not lock file %s: %s\n", LOCKFILE, strerror(errno));
			/* do not close(fd) */
			exit(EXIT_FAILURE);
		}
	}
	/* success to add a record lock to lockfile, and write a daemon process id to it */
	ftruncate(fd, 0);	/* empty a file */
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf)+1);
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

static start_report() {
	FILE *fp = NULL;
	truncate(WRITEFLAG, 0);		/* clear file content */
	fp = fopen(WRITEFLAG, "w+");
	if (fp == NULL) {
		syslog(LOG_ERR, "Error: failed to open file %s .\n%s", WRITEFLAG, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fputs("1", fp);
	fclose(fp);
}

static end_report() {
	FILE *fp = NULL;
	truncate(WRITEFLAG, 0);
	fp = fopen(WRITEFLAG, "w+");
	if (fp == NULL) {
		syslog(LOG_ERR, "Error: failed to open file %s .\n%s", WRITEFLAG, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	fputs("0", fp);
	fclose(fp);
}
void * thr_fn(void *arg) {
	while (1) {
		/* lock_lock(&lock); there is a lock in report_statistic */
		start_report();
		report_statistic(ssp, &vsp);
		end_report();
		/* unlock_lock(&lock); */
		syslog(LOG_INFO, "reported statistic.\n"); 
		sleep(TS);
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
