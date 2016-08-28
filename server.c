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

#include "server_opt.h"

#define SERVER_CERT			"cert.pem"
#define SERVER_KEY			SERVER_CERT
#define SESSION_MAX			1
#define MAX_SESSION_PER_THREAD 16
#define STATS_UPDATE_FREQ	1

#define MAX_PACKET_SIZE;

typedef struct {
	SSL *ssl;
	int in;
	int out;
  /** buffer used to get output of SSL_read */
  unsigned char* read_buf;
  /** buffer used as input to SSL_write */
  unsigned char* write_buf;
  /** wait on async offload for async read */
  int async_wait_read;
  /** wait on async offload for async write */
  int async_wait_write;
  /** size arguments for write buf */
  int write_size;
} ssl_session_t;

typedef struct {
  ssl_session_t sessions[MAX_SESSION_PER_THREAD];
	pthread_t thread;
	int tid;
	stats_t stats;
} __attribute__((aligned(64))) ssl_worker_t;

ssl_worker_t workers[2*SESSION_MAX];

/** Initialize a session structure */
static void init_session(ssl_session_t* session, SSL* ssl, int in, int out)
{
  session->ssl = ssl;
  session->in  = in;
  session->out = out;

  session->read_buf = malloc(sizeof(unsigned char) * MAX_PACKET_SIZE);
  session->write_buf = malloc(sizeof(unsigned char) * MAX_PACKET_SIZE);

  session->async_wait_write = session->async_wait_read = 0;
  session->write_size = 0;
}

/** Clear a session structure */
static void clean_session(ssl_session_t* session) 
{
  free(session->read_buf);
  free(session->write_buf);
}


static void * ssl_session(void *_session)
{
	ssl_session_t *session = _session;
	SSL *ssl = session->ssl;
	int in = session->in;
	int out = session->out;
  unsigned char* read_buf = session->read_buf;
  unsigned char* write_buf = session->write_buf;

	int sock = SSL_get_fd(ssl);
	ASSERT_SSL(sock >= 0);
	int nfds = (sock < in ? in : sock) + 1;

	for (;;) {
		timestats_t ts;
		timestats_start(&ts);
		for (int i=0; i<STATS_UPDATE_FREQ; i++) {
      fd_set rfds;
      FD_ZERO(&rfds);

      if (!session->async_wait_read && !async_wait_write) 
      {
        // only select a socket/pipe-out if no async offload operation is pending (simplification)
			  FD_SET(sock, &rfds);
			  FD_SET(in, &rfds);

        int err = select(nfds, &rfds, NULL, NULL, NULL);
        ASSERT(-1 != err, "select()");

      }

      if (session->async_wait_read && FD_ISSET(sock, &rfds)) 
      {
        session->async_wait_read = 0;
				err = SSL_read(ssl, session->read_buf, MAX_PACKET_SIZE);
				if (0 == err) return 0;
        if (err < 0) {
          int ssl_err;
          switch (ssl_err = SSL_get_error(ssl, err)) {
          case SSL_ERROR_WANT_ASYNC:
            session->async_wait_read = 1;
            break;
          default:
            assert(0 && "unsupported error code");
            break;
          }
        } else {
          ASSERT_SSL(PACKET_SIZE == err);
          err = write(out, session->read_buf, err);
          if (0 == err) return 0;
          ASSERT(PACKET_SIZE == err, "write()");
        }
      };

      if (FD_ISSET(in, &rfds) || session->async_wait_write) 
      {
        // reading from pipe output
        if (FD_ISSET(in, &rfds)) {
          err = read(in, session->write_buf, MAX_PACKET_SIZE);
          if (0 == err) return 0;
          ASSERT(MAX_PACKET_SIZE == err, "read()");
          session->write_size = err;
        }

        // trying to write read data to secure connection
        session->async_wait_write = 0;
				err = SSL_write(ssl, session->write_buf, session->write_size);
        if (err < 0) {
          int ssl_err;
          switch (ssl_err = SSL_get_error(ssl, err)) {
          case SSL_ERROR_WANT_ASYNC:
            session->async_wait_write = 1;
            break;
          default:
            assert(0 && "unsupported error code");
            break;
          }
        } else {
          if (0 == err) return 0;
          ASSERT_SSL(PACKET_SIZE == err);
        }
      }

      // explicit yield 
      ASYNC_pause_job();
		}
		timestats_stop(&ts);
		stats_update(&worker->stats, STATS_UPDATE_FREQ, PACKET_SIZE, &ts);
	}
	return NULL;
}

static void * ssl_worker(void *worker_)
{
	static __thread char buf[PACKET_SIZE];
	ssl_worker_t *worker = worker_;
	SSL *ssl = worker->ssl;
	int in = worker->in;
	int out = worker->out;

	int sock = SSL_get_fd(ssl);
	ASSERT_SSL(sock >= 0);
	int nfds = (sock < in ? in : sock) + 1;
	fd_set rfds;
	FD_ZERO(&rfds);

	for (;;) {
		timestats_t ts;
		timestats_start(&ts);
		for (int i=0; i<STATS_UPDATE_FREQ; i++) {
			FD_SET(sock, &rfds);
			FD_SET(in, &rfds);
			int err = select(nfds, &rfds, NULL, NULL, NULL);
			ASSERT(-1 != err, "select()");
			if (FD_ISSET(sock, &rfds)) {
				err = SSL_read(ssl, buf, sizeof(buf));
				if (0 == err) return 0;
				ASSERT_SSL(sizeof(buf) == err);
				err = write(out, buf, err);
				if (0 == err) return 0;
				ASSERT(sizeof(buf) == err, "write()");
			}
			if (FD_ISSET(in, &rfds)) {
				err = read(in, buf, sizeof(buf));
				if (0 == err) return 0;
				ASSERT(sizeof(buf) == err, "read()");
				err = SSL_write(ssl, buf, err);
				if (0 == err) return 0;
				ASSERT_SSL(sizeof(buf) == err);
			}
		}
		timestats_stop(&ts);
		stats_update(&worker->stats, STATS_UPDATE_FREQ, PACKET_SIZE, &ts);
	}
	return NULL;
}

static void ssl_worker_spawn(int tid, SSL *ssl, int in, int out)
{
	workers[tid].ssl = ssl;
	workers[tid].in = in;
	workers[tid].out = out;
	workers[tid].tid = tid;
	int err = pthread_create(&workers[tid].thread, NULL, ssl_worker, &workers[tid]);
	ASSERT(0 == err, "pthread_create(ssl_worker) failed");
}

static int ssl_listen(int port)
{
	int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT(sock >= 0, "socket");

	struct sockaddr_in sa_serv;
	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port);
	int err = bind(sock, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
	ASSERT(0 == err, "bind()");

	err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
	ASSERT(0 == err, "setsockopt");

	err = listen(sock, 5);
	ASSERT(0 == err, "listen");

	return sock;
}

static SSL * ssl_accept(SSL_CTX *ctx, int listen_sock)
{
	struct sockaddr_in sa_cli;
	int sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t[]){sizeof(sa_cli)});
	ASSERT(sock >= 0, "accept");

	fprintf(stderr, "Connection from %x, port %x\n", sa_cli.sin_addr.s_addr,
			sa_cli.sin_port);

	SSL *ssl = SSL_new(ctx);
	ASSERT_SSL(ssl);

	SSL_set_fd(ssl, sock);
	SSL_set_accept_state(ssl);

	return ssl;
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
  struct server_opt_args_info args_info;
  if (server_opt_cmdline_parser(argc, argv, &args_info) != 0)
    exit(1);

	int port = args_info.port_arg;

	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth = SSLv23_method();
	SSL_CTX *ctx = SSL_CTX_new(meth);
	ASSERT_SSL(ctx);
	int err = SSL_CTX_set_cipher_list(ctx, args_info.cipher_arg);
	ASSERT_SSL(1 == err);

	err = SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);
	err = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);

	int sock = ssl_listen(port);

	printf("Server started on port %i with ciphers %s...\n", port, argv[2]);

	for (int i=0; i<SESSION_MAX; i++) {
		SSL *ssl1 = ssl_accept(ctx, sock);
		SSL *ssl2 = ssl_accept(ctx, sock);
		int pipe1[2], pipe2[2];
		err = pipe(pipe1);
		ASSERT(0 == err, "pipe()");
		err = pipe(pipe2);
		ASSERT(0 == err, "pipe()");
		ssl_worker_spawn(2*i+0, ssl1, pipe1[0], pipe2[1]);
		ssl_worker_spawn(2*i+1, ssl2, pipe2[0], pipe1[1]);
	}

	for (;;) {
		sleep(1);
		dump_stats();
	}

	return 0;
}
