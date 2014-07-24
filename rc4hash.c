#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "rc4.h"
#include "rc4hash.h"

static struct rc4 salt_generator;

static void salt_init() {
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

void print_usage(FILE *out) {
    fprintf(out, "Usage: rc4hash [options]\n");
    fprintf(out, "  -p <password>    Password to be hashed (required)\n");
    fprintf(out, "  -v <hex hash>    Validates hash against given password\n");
    fprintf(out, "  -d <difficulty>  Difficulty factor (0-255, default: 18)\n");
    fprintf(out, "  -s <hex salt>    Hardcoded salt value (default: random)\n");
}

int main(int argc, char **argv) {
    struct rc4hash hash = {salt_generate(), 18};
    char *p = NULL, *v = NULL;

    /* Parse command line. */
    int opt;
    while ((opt = getopt(argc, argv, "d:s:p:v:")) >= 0) {
        switch (opt) {
        case 'd':
            hash.difficulty = strtol(optarg, NULL, 10);
            break;
        case 's':
            hash.salt = htonl(strtoll(optarg, NULL, 16));
            break;
        case 'p':
            p = optarg;
            break;
        case 'v':
            v = optarg;
            break;
        case '?':
            print_usage(stderr);
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

    if (v != NULL) {
        /* Verify */
        rc4hash_parse(&hash, v);
        if (rc4hash_verify(&hash, p)) {
            printf("valid\n");
            exit(EXIT_SUCCESS);
        } else {
            printf("invalid\n");
            exit(EXIT_FAILURE);
        }
    } else {
        /* Hash */
        rc4hash(&hash, p);
        rc4hash_print(&hash, stdout);
        putchar('\n');
    }
    return 0;
}
