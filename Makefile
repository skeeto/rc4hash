CC     = clang
CFLAGS = -std=c99 -O3 -Wall

rc4hash : rc4hash.c

run : rc4hash
	./$^ -p testpw
	./$^ -p testpw -v 35fe67960003ffff16ccb2b84fc68636d211db12fc01b2b36cb32f79
