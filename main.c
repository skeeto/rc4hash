#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include "rc4hash.h"

void print_usage(FILE *out) {
    fprintf(out, "Usage: rc4hash [options]\n");
    fprintf(out, "  -p <password>    Password to be hashed\n");
    fprintf(out, "  -i               Read password from stdin\n");
    fprintf(out, "  -b               Print hash in binary\n");
    fprintf(out, "  -v <hex hash>    Validates hash against given password\n");
    fprintf(out, "  -d <difficulty>  Difficulty factor (0-255, default: 18)\n");
    fprintf(out, "  -s <hex salt>    Hardcoded salt value (default: random)\n");
}

static char *slurp(FILE *in) {
    size_t size = 256, count = 0;
    char *buffer = malloc(size);
    while (!feof(in)) {
        count += fread(buffer + count, 1, size - count, in);
        if (count == size) {
            size *= 2;
            buffer = realloc(buffer, size);
        }
    }
    buffer[count] = '\0';
    return buffer;
}

int main(int argc, char **argv) {
    struct rc4hash hash = {salt_generate(), 18};
    char *p = NULL, *v = NULL;
    bool binary = false;

    /* Parse command line. */
    int opt;
    while ((opt = getopt(argc, argv, "ibd:s:p:v:")) >= 0) {
        switch (opt) {
        case 'i':
            p = slurp(stdin);
            break;
        case 'b':
            binary = true;
            break;
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
        fprintf(stderr, "error: no password specified (-p, -i)\n");
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
        if (binary) {
            char buffer[RC4HASH_SIZE];
            rc4hash_pack(&hash, buffer);
            fwrite(buffer, RC4HASH_SIZE, 1, stdout);
        } else {
            rc4hash_print(&hash, stdout);
            putchar('\n');
        }
    }
    return 0;
}
