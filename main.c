#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include "rc4hash.h"

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
