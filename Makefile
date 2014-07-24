CC     = clang
CFLAGS = -std=c99 -O3 -Wall

rc4hash : main.o rc4hash.o rc4.o

rc4.o : rc4.c rc4.h
rc4hash.o : rc4hash.c rc4hash.h rc4.h
main.o : main.c rc4hash.h

.PHONY : run clean

clean :
	$(RM) *.o rc4hash

run : rc4hash
	./$^ -p testpw
	./$^ -p testpw -v 737b027e122ce0f738a8530c3b56aab22c89a10375c1ededeeb0
