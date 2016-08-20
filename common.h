#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

#define PACKET_SIZE	300

#define ASSERT(cond, str)	if (!(cond)) { perror(str); abort(); }
#define ASSERT_SSL(cond)	if (!(cond)) { fprintf(stderr, "SSL failed: "); ERR_print_errors_fp(stderr); abort(); }

#endif	/* COMMON_H_ */
