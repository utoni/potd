#ifndef POTD_CAPABILITIES_H
#define POTD_CAPABILITIES_H 1

#include <stdint.h>


void caps_check_list(const char *clist, void (*callback)(int));

void caps_print(void);

void caps_drop_dac_override(int noprofile);

int caps_default_filter(void);

int caps_jail_filter(void);

void caps_drop_all(void);

void caps_set(uint64_t caps);

void caps_drop_list(const char *clist);

void caps_keep_list(const char *clist);

#endif
