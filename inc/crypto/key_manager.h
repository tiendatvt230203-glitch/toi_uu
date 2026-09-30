#ifndef CORE_KEY_MANAGER_H
#define CORE_KEY_MANAGER_H
#include <stddef.h>
#include <stdint.h>
int core_key_get(int policy_id, uint8_t *key, size_t key_size);
#endif
