#ifndef BLACKLIST_H
#define BLACKLIST_H

void init_blacklist(const char *filename);
int is_blacklisted(const char *ip);

#endif
