#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "rc4.h"
#include "rc4hash.h"

static struct rc4 entropy_pool;

static void entropy_init() {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        fprintf(stderr, "error: could not seed entropy pool\n");
        exit(EXIT_FAILURE); // emergency bailout
    }
    char seed[256];
    size_t count = sizeof(seed);
    while (count > 0) {
        count -= fread(&seed, 1, count, urandom);
    }
    fclose(urandom);
    rc4_init(&entropy_pool);
    rc4_schedule(&entropy_pool, seed, sizeof(seed));
    rc4_skip(&entropy_pool, 4096);
}

void entropy_get(void *buffer, size_t count) {
    if (entropy_pool.S[0] == entropy_pool.S[1]) {
        entropy_init();
    }
    rc4_emit(&entropy_pool, buffer, count);
}

uint32_t salt_generate() {
    uint32_t salt;
    entropy_get(&salt, sizeof(salt));
    return salt;
}

void rc4hash(struct rc4hash *hash, const char *password) {
    struct rc4 rc4;
    rc4_init(&rc4);
    rc4_schedule(&rc4, (char *) &hash->salt, sizeof(hash->salt));

    /* Run scheduler 2^difficulty times. */
    char buffer[256];
    size_t length = strlen(password);
    memcpy(buffer, password, length);
    rc4_emit(&rc4, buffer + length, sizeof(buffer) - length);
    for (uint64_t i = 0; i <= 1 << hash->difficulty; i++) {
        rc4_schedule(&rc4, buffer, sizeof(buffer));
    }

    /* Skip 2^(difficulty+6)-1 bytes of output. */
    rc4_skip(&rc4, (1 << (hash->difficulty + 6)) - 1);

    /* Emit output. */
    rc4_emit(&rc4, hash->hash, RC4HASH_SIZE - RC4HASH_HEADER_SIZE);
}

void rc4hash_pack(const struct rc4hash *hash, void *buffer) {
    memcpy(buffer, &hash->salt, sizeof(hash->salt));
    memcpy(buffer + sizeof(hash->salt), &hash->difficulty, 1);
    memcpy(buffer + sizeof(hash->salt) + 1, &hash->hash, sizeof(hash->hash));
}

void rc4hash_unpack(struct rc4hash *hash, const char *input) {
    memcpy(&hash->salt, input, sizeof(hash->salt));
    memcpy(&hash->difficulty, input + sizeof(hash->salt), 1);
    memcpy(&hash->hash, input + RC4HASH_HEADER_SIZE,
           RC4HASH_SIZE - RC4HASH_HEADER_SIZE);
}

void rc4hash_print(const struct rc4hash *hash, FILE *out) {
    uint8_t packed[RC4HASH_SIZE];
    rc4hash_pack(hash, packed);
    for (int i = 0; i < RC4HASH_SIZE; i++) {
        fprintf(out, "%02x", packed[i]);
    }
}

void rc4hash_parse(struct rc4hash *hash, const char *input) {
    uint8_t extract[RC4HASH_SIZE];
    char n[3] = {0};
    for (int i = 0; i < RC4HASH_SIZE; i++) {
        memcpy(n, input + i * 2, 2);
        extract[i] = strtol(n, NULL, 16);
    }
    rc4hash_unpack(hash, (char *) extract);
}

bool rc4hash_verify(const struct rc4hash *hash, const char *password) {
    struct rc4hash compare = {hash->salt, hash->difficulty};
    rc4hash(&compare, password);
    int check = 0;
    for (int i = 0; i < RC4HASH_SIZE - RC4HASH_HEADER_SIZE; i++) {
        check |= hash->hash[i] ^ compare.hash[i];
    }
    return check == 0;
}
