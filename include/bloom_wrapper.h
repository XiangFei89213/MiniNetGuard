#ifndef BLOOM_WRAPPER_H
#define BLOOM_WRAPPER_H

#include <stdbool.h>

// 初始化 Bloom filter
void bloom_initialize(int size, double error_rate);

// 增加 IP 到 Bloom filter
void bloom_add_ip(const char *ip);

// 檢查 IP 是否在黑名單中
bool bloom_check_ip(const char *ip);

// 釋放記憶體
void bloom_cleanup();

#endif
