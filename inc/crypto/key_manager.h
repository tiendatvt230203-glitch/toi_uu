#ifndef CORE_KEY_MANAGER_H
#define CORE_KEY_MANAGER_H
#include <stddef.h>
#include <stdint.h>
struct pqc_policy_input;

int core_key_install(int policy_id, const uint8_t *key, size_t key_size);
int core_key_get(int policy_id, uint8_t *key, size_t key_size);
int core_key_request(const struct pqc_policy_input *policy);
void core_key_remove(int policy_id);
#endif
