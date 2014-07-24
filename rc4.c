#include <stdlib.h>
#include <stdint.h>
#include "rc4.h"

#define SWAP(a, b) if (a ^ b) {a ^= b; b ^= a; a ^= b;}

void rc4_init(struct rc4 *k) {
    k->i = k->j = 0;
    for (int i = 0; i < 256; i++) k->S[i] = i;
}

void rc4_schedule(struct rc4 *k, const char *key, size_t length) {
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + k->S[i] + ((uint8_t *)key)[i % length]) % 256;
        SWAP(k->S[i], k->S[j]);
    }
}

static uint8_t rc4_emit_byte(struct rc4 *k) {
    k->j += k->S[++k->i];
    SWAP(k->S[k->i], k->S[k->j]);
    return k->S[(k->S[k->i] + k->S[k->j]) & 0xFF];
}

void rc4_emit(struct rc4 *k, void *buffer, size_t count) {
    for (size_t b = 0; b < count; b++) {
        ((uint8_t *)buffer)[b] = rc4_emit_byte(k);
    }
}

void rc4_skip(struct rc4 *k, size_t count) {
    for (size_t b = 0; b < count; b++) {
        rc4_emit_byte(k);
    }
}
