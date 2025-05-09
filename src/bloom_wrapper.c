#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bloom_wrapper.h"
#include "bloom.h"
#include "/usr/local/include/bloom.h"


static struct bloom filter;

// 初始化 Bloom filter
void bloom_initialize(int size, double error_rate) {
    printf("[*] Initializing Bloom Filter with size %d and error rate %.2f\n", size, error_rate);
    bloom_init(&filter, size, error_rate);
}

// 增加 IP 到 Bloom filter
void bloom_add_ip(const char *ip) {
    bloom_add(&filter, ip, strlen(ip));
    printf("[*] Added IP to Bloom Filter: %s\n", ip);
}

// 檢查 IP 是否在黑名單中
bool bloom_check_ip(const char *ip) {
    return bloom_check(&filter, ip, strlen(ip));
}

// 釋放記憶體
void bloom_cleanup() {
    bloom_free(&filter);
}
