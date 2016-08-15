#ifndef STATS_H_
#define STATS_H_

#include <time.h>

typedef struct {
	unsigned long long pkt;
	double bw_gbps;
	double cpu_load;
} stats_t;

typedef struct {
	struct timespec wall;
	struct timespec cpu;
} timestats_t;
#define S2NS			(1000000000)
#define timespec2ns(ts)	((ts)->tv_sec * S2NS + (ts)->tv_nsec)

static inline void stats_update(stats_t *stats, unsigned long long pkt, int size, const timestats_t *ts)
{
	stats->pkt += pkt;
	stats->bw_gbps = (double)pkt * size * 8 / timespec2ns(&ts->wall);
	stats->cpu_load = (double)timespec2ns(&ts->cpu) * 100 / timespec2ns(&ts->wall);
}

static inline void timestats_start(timestats_t *ts)
{
	clock_gettime(CLOCK_MONOTONIC, &ts->wall);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts->cpu);
}

static inline void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;
	if (a->tv_nsec >= b->tv_nsec) {
		c->tv_nsec = a->tv_nsec - b->tv_nsec;
	} else {
		c->tv_nsec = a->tv_nsec + S2NS - b->tv_nsec;
		c->tv_sec--;
	}
}

static inline void timestats_stop(timestats_t *ts)
{
	struct timespec w_stop, c_stop;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c_stop);
	clock_gettime(CLOCK_MONOTONIC, &w_stop);
	timespecsub(&w_stop, &ts->wall, &ts->wall);
	timespecsub(&c_stop, &ts->cpu, &ts->cpu);
}

#endif	/* STATS_H_ */
