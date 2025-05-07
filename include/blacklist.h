#ifndef BLACKLIST_H
#define BLACKLIST_H

#include "bloom.h"

void init_blacklist(const char *filename);
int is_blacklisted(const char *ip);

#endif
