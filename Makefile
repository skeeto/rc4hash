CC     = clang
CFLAGS = -std=c99 -O3 -Wall

rc4hash : rc4hash.c

run : rc4hash
	./$^ -p testpw
	./$^ -p testpw -v c74118470003ffff53c331eb8f526fe6e70a91b0f5608ae8c95e75ae
