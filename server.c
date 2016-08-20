#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common.h"
#include "stats.h"

#define SERVER_CERT			"cert.pem"
#define SERVER_KEY			SERVER_CERT
#define SESSION_MAX			1
#define STATS_UPDATE_FREQ	1

typedef struct {
	BIO *ssl_in;
	BIO *ssl_out;
	int in;
	int out;
	pthread_t thread;
	int tid;
	stats_t stats;
} __attribute__((aligned(64))) ssl_worker_t;

ssl_worker_t workers[2*SESSION_MAX];

static void * ssl_worker(void *worker_)
{
	static __thread char buf[PACKET_SIZE];
	ssl_worker_t *worker = worker_;
	BIO *ssl_in = worker->ssl_in;
	BIO *ssl_out = worker->ssl_out;
	int in = worker->in;
	int out = worker->out;

	fd_set rfds;
	FD_ZERO(&rfds);

	timestats_t ts;
	timestats_start(&ts);
	int pkt = 0;
	for (;;) {
		FD_SET(in, &rfds);
		int err = select(in+1, &rfds, NULL, NULL, (struct timeval[]){{0,100}});
		ASSERT(-1 != err, "select()");
		if (FD_ISSET(in, &rfds)) {
			err = read(in, buf, sizeof(buf));
			if (0 == err) break;
			ASSERT(sizeof(buf) == err, "read()");
			err = BIO_write(ssl_out, buf, err);
			ASSERT_SSL(err >= 0)
			if (0 == err) break;
			if (err < sizeof(buf)) {
				/* partial write happens when buffer_w_bio is full */
				int rem = sizeof(buf) - err;
				err = BIO_write(ssl_out, &buf[err], rem);
				ASSERT_SSL(err == rem);
			}
			pkt++;
		}
		err = BIO_read(ssl_in, buf, sizeof(buf));
		if (0 != err) {
			ASSERT_SSL(sizeof(buf) == err);
			err = write(out, buf, err);
			if (0 == err) break;
			ASSERT(sizeof(buf) == err, "write()");
			pkt++;
		}
		if (STATS_UPDATE_FREQ <= pkt) {
			timestats_stop(&ts);
			stats_update(&worker->stats, pkt, PACKET_SIZE, &ts);
			pkt = 0;
			timestats_start(&ts);
		}
	}
	return NULL;
}

static void ssl_worker_spawn(int tid, BIO *bio[2], int in, int out)
{
	workers[tid].ssl_in = bio[0];
	workers[tid].ssl_out = bio[1];
	workers[tid].in = in;
	workers[tid].out = out;
	workers[tid].tid = tid;
	int err = pthread_create(&workers[tid].thread, NULL, ssl_worker, &workers[tid]);
	ASSERT(0 == err, "pthread_create(ssl_worker) failed");
}

static BIO * ssl_listen(const char *port, BIO *ssl_bio)
{
	BIO *accept_bio = BIO_new_accept(port);
	ASSERT_SSL(accept_bio);
	BIO_set_accept_bios(accept_bio, ssl_bio);
	int err = BIO_do_accept(accept_bio);
	ASSERT_SSL(err > 0);
	return accept_bio;
}

static void ssl_accept(BIO *bio[2], BIO *accept_bio)
{
	int err = BIO_do_accept(accept_bio);
	ASSERT_SSL(err > 0);
	BIO *ssl_bio = BIO_pop(accept_bio);
	err = BIO_do_handshake(ssl_bio);
	ASSERT_SSL(err > 0);
	/*
	 * Abusing SSL bio here...
	 * bio chain is accept<-->ssl<-->socket
	 * break it apart and rebuild to
	 *   read:  socket --> buffer --> ssl
	 *   write: buffer --> ssl --> socket
	 * As crypto ops happened in SSL bio,
	 * we buffer data before reading or writing
	 * to SSL to maximize performance
	 */
	BIO *sock_bio = BIO_pop(ssl_bio);
	BIO *buffer_r_bio = BIO_new(BIO_f_buffer());
	ASSERT_SSL(buffer_r_bio);
	/*
	 * read:  buffer --> ssl
	 * write: ssl --> socket
	 */
	SSL *ssl;
	BIO_get_ssl(ssl_bio, &ssl);
	ASSERT_SSL(ssl);
	SSL_set_bio(ssl, buffer_r_bio, sock_bio);
	/* write: buffer --> ssl --> socket */
	BIO *buffer_w_bio = BIO_new(BIO_f_buffer());
	ASSERT_SSL(buffer_w_bio);
	BIO_push(buffer_w_bio, ssl_bio);
	/* read: socket --> buffer --> ssl */
	BIO_push(buffer_r_bio, sock_bio);

	bio[0] = ssl_bio;
	bio[1] = buffer_w_bio;
}

static void dump_worker_stats__(const stats_t *stats, const char *fmt, ...)
{
	printf("STATS ");
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf(" %llu packets (%g Gbps) - %g CPU load\n", stats->pkt, stats->bw_gbps, stats->cpu_load);
}

static void stats_add(const stats_t *a, const stats_t *b, stats_t *c)
{
	c->pkt      = a->pkt      + b->pkt;
	c->bw_gbps  = a->bw_gbps  + b->bw_gbps;
	c->cpu_load = a->cpu_load + b->cpu_load;
}

static void dump_worker_stats(int tid, stats_t *acc)
{
	const stats_t *stats = &workers[tid].stats;
	stats_add(stats, acc, acc);
	dump_worker_stats__(stats, "thr %i", tid);
}

static void dump_stats(void)
{
	stats_t stats = {};
	for (int tid=0; tid<2*SESSION_MAX; tid++) {
		dump_worker_stats(tid, &stats);
	}
	dump_worker_stats__(&stats, "TOTAL ");
}

int main(int argc, const char **argv)
{
	if (3 != argc) {
		fprintf(stderr, "Usage: %s <port> <cipher>\n", argv[0]);
		exit(-1);
	}
	const char *port = argv[1];
	const char *cipher = argv[2];

	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth = SSLv23_method();
	SSL_CTX *ctx = SSL_CTX_new(meth);
	ASSERT_SSL(ctx);
	int err = SSL_CTX_set_cipher_list(ctx, argv[2]);
	ASSERT_SSL(1 == err);

	err = SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);
	err = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);

	BIO *ssl_bio = BIO_new_ssl(ctx, 0);
	ASSERT_SSL(ssl_bio);
	SSL *ssl;
	BIO_get_ssl(ssl_bio, &ssl);
	ASSERT_SSL(ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO *accept_bio = ssl_listen(port, ssl_bio);

	printf("Server started on port %s with ciphers %s...\n", port, cipher);

	for (int i=0; i<SESSION_MAX; i++) {
		BIO *bio1[2], *bio2[2];
		ssl_accept(bio1, accept_bio);
		ssl_accept(bio2, accept_bio);
		int pipe1[2], pipe2[2];
		err = pipe(pipe1);
		ASSERT(0 == err, "pipe()");
		err = pipe(pipe2);
		ASSERT(0 == err, "pipe()");
		ssl_worker_spawn(2*i+0, bio1, pipe1[0], pipe2[1]);
		ssl_worker_spawn(2*i+1, bio2, pipe2[0], pipe1[1]);
	}

	BIO_free_all(accept_bio);

	for (;;) {
		sleep(1);
		dump_stats();
	}

	return 0;
}
