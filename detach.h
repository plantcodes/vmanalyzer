/* filename: detach.h
 * declear daemonize function, thread function,
 * signal handler 
 */

#ifndef DETACH_H
#define DETACH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <syslog.h>

/* detach the process from terminal 
 */
extern void daemonize(void);

/* get lock
 * set default mutex attributes with NULL
 */
extern void get_lock(pthread_mutex_t *lockp);

/* free lock
 */
extern void free_lock(pthread_mutex_t *lockp);

/* lock lock
 */
extern void lock_lock(pthread_mutex_t *lockp);

/* unlock lock
 */
extern void unlock_lock(pthread_mutex_t *lockp);

/* thread function
 * does report operation periodically
 * and erases rp, sp, tp in this period.
 */
extern void * thr_fn(void *arg);

/* create_thread
 * use ptread_create function,
 * and add error handler
 */
extern void create_thread(pthread_t *tidp, void *(*thr_fn)(void *));

/* signal handlers
 * handle SIGINT, SIGTERM(the signal kill send defaultly)
 * free memory, close pcap_t *, destory lock
 */
extern void sig_int(int signo);
extern void sig_term(int signo);
extern void sig_tstp(int signo);

/* install signal handlers
 * signo: the signal number
 * sighdl: signal handler function pointer
 */
extern void install_sighdl(int signo, void (*sighdl)(int));

#endif
