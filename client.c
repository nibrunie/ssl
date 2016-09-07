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

int main(int argc, const char **argv)
{
	if (4 != argc) {
		fprintf(stderr, "Usage: %s <host> <port> <cipher>\n", argv[0]);
		exit(-1);
	}
	struct in_addr addr;
	int err = inet_aton(argv[1], &addr);
	ASSERT(err != 0, "inet_aton()");
	int port = atoi(argv[2]);
	const char *cipher = argv[3];

	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth = SSLv23_method();
	SSL_CTX *ctx = SSL_CTX_new(meth);
	ASSERT_SSL(ctx);
	err = SSL_CTX_set_cipher_list(ctx, cipher);
	ASSERT_SSL(1 == err);

	int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT(sock >= 0, "socket");

	struct sockaddr_in sa = {};
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	sa.sin_port = htons(port);
	err = connect(sock, (void *)&sa, sizeof(sa));
	ASSERT(0 == err, "connect()");

	SSL *ssl = SSL_new(ctx);
	ASSERT_SSL(ssl);
	SSL_set_fd(ssl, sock);
	err = SSL_connect(ssl);
	ASSERT_SSL(1 == err);

	fd_set rfds;
	FD_ZERO(&rfds);

	for (;;) {
		static __thread char buf[PACKET_SIZE];
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(sock, &rfds);
		err = select(sock+1, &rfds, NULL, NULL, NULL);
		ASSERT(-1 != err, "select()");
		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			err = read(STDIN_FILENO, buf, sizeof(buf));
			if (0 == err) break;
			ASSERT(sizeof(buf) == err, "read()");
			err = SSL_write(ssl, buf, err);
			if (0 == err) break;
			ASSERT_SSL(sizeof(buf) == err);
		}
		if (FD_ISSET(sock, &rfds)) {
			err = SSL_read(ssl, buf, sizeof(buf));
			if (0 == err) break;
			ASSERT_SSL(sizeof(buf) == err);
			err = write(STDOUT_FILENO, buf, sizeof(buf));
			if (0 == err) break;
			ASSERT_SSL(sizeof(buf) == err);
		}
	}

	return 0;
}
