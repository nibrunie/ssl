#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSZ		300
#define SERVER_CERT	"cert.pem"
#define SERVER_KEY	SERVER_CERT

#define ASSERT(cond, str)	if (!(cond)) { perror(str); exit(1); }
#define ASSERT_SSL(cond)	if (!(cond)) { ERR_print_errors_fp(stderr); exit(1); }

int main(int argc, const char **argv)
{
	if (2 != argc) {
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		exit(-1);
	}
	int port = atoi(argv[1]);

	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth = TLSv1_2_method();
	SSL_CTX *ctx = SSL_CTX_new(meth);
	ASSERT_SSL(ctx);
	int err = SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384");
	ASSERT_SSL(1 == err);

	err = SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);
	err = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM);
	ASSERT_SSL(1 == err);

	int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT(listen_sock >= 0, "socket");
	struct sockaddr_in sa_serv;
	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port);
	err = bind(listen_sock, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
	ASSERT(0 == err, "bind");
	err = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
	ASSERT(0 == err, "setsockopt");
	err = listen(listen_sock, 5);
	ASSERT(0 == err, "listen");
	struct sockaddr_in sa_cli;
	int sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t[]){sizeof(sa_cli)});
	ASSERT(sock >= 0, "accept");
	close(listen_sock);

	fprintf(stderr, "Connection from %x, port %x\n", sa_cli.sin_addr.s_addr,
			sa_cli.sin_port);

	SSL *ssl = SSL_new(ctx);
	ASSERT_SSL(ssl);

	SSL_set_fd(ssl, sock);
	err = SSL_accept(ssl);
	ASSERT_SSL(1 == err);

	fprintf(stderr, "SSL connection using %s\n", SSL_get_cipher(ssl));

	fd_set rfds;
	FD_ZERO(&rfds);

	for (;;) {
		FD_SET(sock, &rfds);
		FD_SET(STDIN_FILENO, &rfds);
		err = select(sock+1, &rfds, NULL, NULL, NULL);
		ASSERT(-1 != err, "select");

		static char buf[BUFSZ];

		if (FD_ISSET(sock, &rfds)) {
			err = SSL_read(ssl, buf, sizeof(buf));
			ASSERT_SSL(err >= 0);
			if (0 == err) break;
			write(STDOUT_FILENO, buf, err);
		}

		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			err = read(STDIN_FILENO, buf, sizeof(buf));
			ASSERT(err >= 0, "read");
			if (0 == err) break;
			err = SSL_write(ssl, buf, err);
			ASSERT_SSL(err >= 0);
		}
	}

	SSL_shutdown(ssl);
	close(sock);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
