#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blacklist.h"
#include "bloom.h"

static struct bloom bloom_filter;

void init_blacklist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open blacklist file");
        exit(1);
    }

    bloom_init(&bloom_filter, 1000, 0.01); // 設定容量 1000 筆, 1% 錯誤率

    char ip[20];
    while (fgets(ip, sizeof(ip), file)) {
        ip[strcspn(ip, "\n")] = 0; // 去除換行
        bloom_add(&bloom_filter, ip);
        printf("[Bloom Filter] Added IP: %s\n", ip);
    }

    fclose(file);
}

int is_blacklisted(const char *ip) {
    return bloom_check(&bloom_filter, ip);
}
