#ifndef COMMON_H_
#define COMMON_H_

#define PACKET_SIZE	300

#define ASSERT(cond, str)	if (!(cond)) { perror(str); exit(1); }
#define ASSERT_SSL(cond)	if (!(cond)) { ERR_print_errors_fp(stderr); exit(1); }

#endif	/* COMMON_H_ */
