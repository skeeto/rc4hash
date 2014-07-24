#ifndef RC4HASH_RC4_H
#define RC4HASH_RC4_H

#include <stdlib.h>
#include <stdint.h>

struct rc4 {
    uint8_t S[256];
    uint8_t i, j;
};

void rc4_init(struct rc4 *k);
void rc4_schedule(struct rc4 *k, const char *key, size_t length);
void rc4_emit(struct rc4 *k, void *buffer, size_t count);
void rc4_skip(struct rc4 *k, size_t count);

#endif
