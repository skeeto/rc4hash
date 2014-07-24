#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include "rc4hash.h"

struct job {
    char *password, *hash;
    struct job *next;
};

static struct job *jobs = NULL;

struct job *job_last() {
    if (jobs == NULL) {
        return NULL;
    } else {
        struct job *next = jobs;
        while (next->next != NULL) next = next->next;
        return next;
    }
}

void job_push(char *password, char *hash) {
    struct job *job = malloc(sizeof(struct job));
    job->password = password;
    job->hash = hash;
    job->next = NULL;
    if (jobs == NULL) {
        jobs = job;
    } else {
        job_last()->next = job;
    }
}

struct job *job_pop() {
    struct job *next = jobs;
    if (jobs != NULL) jobs = jobs->next;
    return next;
}

void jobs_validate() {
    for (struct job *job = jobs; job != NULL; job = job->next) {
        if (strlen(job->password) > 256) {
            fprintf(stderr, "error: max password length == 256\n");
            exit(EXIT_FAILURE);
        }
    }
}

char *xstrdup(const char *str) {
    char *copy = malloc(strlen(str));
    char *p = copy;
    for (; *str; str++, p++) {
        *p = *str;
    }
    return copy;
}

void print_usage(FILE *out) {
    fprintf(out, "Usage: rc4hash [options]\n");
    fprintf(out, "  -p <password>    Password to be hashed\n");
    fprintf(out, "  -i               Read password from stdin\n");
    fprintf(out, "  -b               Print hash in binary\n");
    fprintf(out, "  -v <hex hash>    Validates hash against given password\n");
    fprintf(out, "  -d <difficulty>  Difficulty factor (0-255, default: 18)\n");
    fprintf(out, "  -s <hex salt>    Choose salt value (default: random)\n\n");
    fprintf(out, "Password and validation arguments can appear multiple\n"
            "times. Each will be processed separately and the program\n"
            "will only return success when all jobs are successful.\n");
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
    uint8_t difficulty = 18;
    uint32_t salt;
    bool binary = false;
    bool gen_salt = true;

    /* Parse command line. */
    int opt;
    while ((opt = getopt(argc, argv, "ibd:s:p:v:")) >= 0) {
        switch (opt) {
        case 'i':
            job_push(slurp(stdin), NULL);
            break;
        case 'b':
            binary = true;
            break;
        case 'd':
            difficulty = strtol(optarg, NULL, 10);
            break;
        case 's':
            gen_salt = false;
            salt = htonl(strtoll(optarg, NULL, 16));
            break;
        case 'p':
            job_push(xstrdup(optarg), NULL);
            break;
        case 'v':
            if (jobs == NULL) {
                fprintf(stderr, "error: specify password option before hash\n");
                exit(EXIT_FAILURE);
            } else if (job_last()->hash == NULL) {
                job_last()->hash = optarg;
            } else {
                job_push(xstrdup(job_last()->password), optarg);
            }
            break;
        case '?':
            print_usage(stderr);
            exit(EXIT_FAILURE);
        }
    }
    jobs_validate();

    /* Process all jobs. */
    while (jobs != NULL) {
        struct job *job = job_pop();
        if (job->hash != NULL) {
            /* Verify */
            struct rc4hash hash;
            rc4hash_parse(&hash, job->hash);
            if (rc4hash_verify(&hash, job->password)) {
                printf("valid\n");
            } else {
                printf("invalid\n");
                exit(EXIT_FAILURE);
            }
        } else {
            /* Hash */
            struct rc4hash hash
                = {gen_salt ? salt_generate() : salt, difficulty};
            rc4hash(&hash, job->password);
            if (binary) {
                char buffer[RC4HASH_SIZE];
                rc4hash_pack(&hash, buffer);
                fwrite(buffer, RC4HASH_SIZE, 1, stdout);
            } else {
                rc4hash_print(&hash, stdout);
                putchar('\n');
            }
        }
        free(job->password);
        free(job);
    }
    return EXIT_SUCCESS;
}
