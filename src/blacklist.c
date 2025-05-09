#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blacklist.h"
#include "bloom_wrapper.h"

void init_blacklist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open blacklist file");
        exit(1);
    }

    bloom_initialize(1000, 0.01);

    char ip[20];
    while (fgets(ip, sizeof(ip), file)) {
        ip[strcspn(ip, "\n")] = 0;  // 去除換行
        bloom_add_ip(ip);
    }

    fclose(file);
}

int is_blacklisted(const char *ip) {
    return bloom_check_ip(ip);
}
