#ifndef RC4HASH_H
#define RC4HASH_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define RC4HASH_SIZE 26
#define RC4HASH_HEADER_SIZE 5

struct rc4hash {
    uint32_t salt;
    uint8_t difficulty;
    uint8_t hash[RC4HASH_SIZE - RC4HASH_HEADER_SIZE];
};

uint32_t salt_generate();
void rc4hash(struct rc4hash *hash, const char *password);
void rc4hash_pack(const struct rc4hash *hash, void *buffer);
void rc4hash_unpack(struct rc4hash *hash, const char *input);
void rc4hash_print(const struct rc4hash *hash, FILE *out);
void rc4hash_parse(struct rc4hash *hash, const char *input);
bool rc4hash_verify(const struct rc4hash *hash, const char *password);

#endif
