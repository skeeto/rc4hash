#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#define RC4HASH_SIZE        28
#define RC4HASH_HEADER_SIZE 8

#define SWAP(a, b) if (a ^ b) {a ^= b; b ^= a; a ^= b;}
#define MIN(a, b) (a < b ? a : b);

struct rc4 {
    uint8_t S[256];
    uint8_t i, j;
};

void rc4_init(struct rc4 *k) {
    k->i = k->j = 0;
    for (int i = 0; i < 256; i++) k->S[i] = i;
}

void rc4_schedule(struct rc4 *k, const uint8_t *key, size_t len) {
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + k->S[i] + key[i % len]) % 256;
        SWAP(k->S[i], k->S[j]);
    }
}

void rc4_emit(struct rc4 *k, uint8_t *buffer, size_t count) {
    size_t b;
    for (b = 0; b < count; b++) {
        k->j += k->S[++k->i];
        SWAP(k->S[k->i], k->S[k->j]);
        buffer[b] = k->S[(k->S[k->i] + k->S[k->j]) & 0xFF];
    }
}

uint32_t salt_generate() {
    uint32_t salt;
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) exit(EXIT_FAILURE); // emergency bailout
    size_t count = sizeof(salt);
    while (count > 0) {
        count -= fread(&salt, 1, count, urandom);
    }
    fclose(urandom);
    return salt;
}

void hash_password(uint8_t output[RC4HASH_SIZE], const char *password,
                   uint32_t difficulty, uint32_t salt) {
    /* Write header. */
    uint32_t ndifficulty = htonl(difficulty);
    memcpy(output, &salt, sizeof(salt));
    memcpy(output + sizeof(salt), &ndifficulty, sizeof(ndifficulty));

    /* Initialize hash function. */
    struct rc4 rc4;
    rc4_init(&rc4);
    rc4_schedule(&rc4, (uint8_t *) &salt, sizeof(salt));

    /* Run scheduler difficulty times. */
    uint8_t buffer[256];
    size_t length = strlen(password);
    memcpy(buffer, password, length);
    rc4_emit(&rc4, buffer + length, sizeof(buffer) - length);
    for (uint64_t i = 0; i <= difficulty; i++) {
        rc4_schedule(&rc4, buffer, sizeof(buffer));
    }

    /* Skip difficulty*64 bytes of output. */
    uint64_t count = difficulty * 64L;
    while (count > 0) {
        size_t amount = MIN(count, sizeof(buffer));
        rc4_emit(&rc4, buffer, amount);
        count -= amount;
    }

    /* Emit output. */
    rc4_emit(&rc4, output + RC4HASH_HEADER_SIZE,
             RC4HASH_SIZE - RC4HASH_HEADER_SIZE);
}

void hash_print(const uint8_t hash[RC4HASH_SIZE]) {
    for (int i = 0; i < RC4HASH_SIZE; i++) printf("%02x", hash[i]);
}

void hash_parse(uint8_t output[RC4HASH_SIZE], const char *input) {
    char n[3] = {0};
    for (int i = 0; i < RC4HASH_SIZE; i++) {
        memcpy(n, input + i * 2, 2);
        output[i] = strtol(n, NULL, 16);
    }
}

bool hash_verify(const uint8_t hash[RC4HASH_SIZE], const char *password) {
    /* Compute the identical hash. */
    uint32_t salt, difficulty;
    memcpy(&salt, hash, sizeof(salt));
    memcpy(&difficulty, hash + sizeof(salt), sizeof(difficulty));
    difficulty = ntohl(difficulty);
    uint8_t compare[RC4HASH_SIZE];
    hash_password(compare, password, difficulty, salt);

    /* Constant time comparison. */
    int check = 0;
    for (int i = 0; i < RC4HASH_SIZE; i++) {
        check |= hash[i] ^ compare[i];
    }
    return check == 0;
}

int main(int argc, char **argv) {
    int opt;
    uint32_t difficulty = 262143;
    uint32_t salt = salt_generate();
    char *p = NULL, *v = NULL;

    /* Parse command line. */
    while ((opt = getopt(argc, argv, "d:p:s:v:")) >= 0) {
        switch (opt) {
        case 'd':
            difficulty = strtoll(optarg, NULL, 10);
            break;
        case 'p':
            p = optarg;
            break;
        case 'v':
            v = optarg;
            break;
        case 's':
            salt = strtoll(optarg, NULL, 10);
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }
    if (p == NULL) {
        fprintf(stderr, "error: must specify a password (-p)\n");
        exit(EXIT_FAILURE);
    } else if (strlen(p) > 256) {
        fprintf(stderr, "error: max password length == 256\n");
        exit(EXIT_FAILURE);
    }

    uint8_t hash[RC4HASH_SIZE];
    if (v != NULL) {
        /* Verify */
        hash_parse(hash, v);
        if (hash_verify(hash, p)) {
            printf("valid\n");
            exit(EXIT_SUCCESS);
        } else {
            printf("invalid\n");
            exit(EXIT_FAILURE);
        }
    } else {
        /* Hash */
        hash_password(hash, p, difficulty, salt);
        hash_print(hash);
        putchar('\n');
    }
    return 0;
}
