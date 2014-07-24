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
	./$^ -p testpw -v f6a6f740126efae27c94b93bc138832eeca746aef2780e734284
