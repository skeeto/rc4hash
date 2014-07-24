#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "rc4.h"
#include "rc4hash.h"

#define RC4HASH_SIZE        26
#define RC4HASH_HEADER_SIZE 5

static struct rc4 salt_generator;

void salt_init() {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        fprintf(stderr, "error: could not seed entropy pool");
        exit(EXIT_FAILURE); // emergency bailout
    }
    char seed[256];
    size_t count = sizeof(seed);
    while (count > 0) {
        count -= fread(&seed, 1, count, urandom);
    }
    fclose(urandom);
    rc4_init(&salt_generator);
    rc4_schedule(&salt_generator, seed, sizeof(seed));
    rc4_skip(&salt_generator, 4096);
}

uint32_t salt_generate() {
    if (salt_generator.S[0] == salt_generator.S[1]) {
        salt_init();
    }
    uint32_t salt;
    rc4_emit(&salt_generator, &salt, sizeof(salt));
    return salt;
}

void hash_password(uint8_t output[RC4HASH_SIZE], const char *password,
                   uint8_t difficulty, uint32_t salt) {
    /* Write header. */
    memcpy(output, &salt, sizeof(salt));
    memcpy(output + sizeof(salt), &difficulty, sizeof(difficulty));

    /* Initialize random generator. */
    struct rc4 rc4;
    rc4_init(&rc4);
    rc4_schedule(&rc4, (char *) &salt, sizeof(salt));

    /* Run scheduler 2^difficulty times. */
    char buffer[256];
    size_t length = strlen(password);
    memcpy(buffer, password, length);
    rc4_emit(&rc4, buffer + length, sizeof(buffer) - length);
    for (uint64_t i = 0; i <= 1 << difficulty; i++) {
        rc4_schedule(&rc4, buffer, sizeof(buffer));
    }

    /* Skip 2^(difficulty+6)-1 bytes of output. */
    rc4_skip(&rc4, (1 << (difficulty + 6)) - 1);

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
    //difficulty = (difficulty);
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
    uint32_t difficulty = 18;
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
