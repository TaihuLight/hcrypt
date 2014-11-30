#ifndef HCRYPT_KEYRING_H
#define HCRYPT_KEYRING_H

#include "hcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif


#define HCRYPT_NUM_ALGORS	8


typedef struct {
	hcrypt_pubkey_t *pk[HCRYPT_NUM_ALGORS];
	hcrypt_prvkey_t *sk[HCRYPT_NUM_ALGORS];
	int count;
} hcrypt_keyring_t;



int hcrypt_keyring_init(hcrypt_keyring_t *kr);
int hcrypt_keyring_generate(hcrypt_keyring_t *kr);
int hcrypt_keyring_num_pubkeys(hcrypt_keyring_t *kr);
int hcrypt_keyring_num_prvkeys(hcrypt_keyring_t *kr);
int hcrypt_keyring_num_keys(hcrypt_keyring_t *kr);
hcrypt_pubkey_t *hcrypt_keyring_get0_pubkey_by_algor(hcrypt_keyring_t *kr, const hcrypt_algor_t *algor);
hcrypt_pubkey_t *hcrypt_keyring_get0_pubkey_by_name(hcrypt_keyring_t *kr, const char *name);
hcrypt_prvkey_t *hcrypt_keyring_get0_prvkey_by_algor(hcrypt_keyring_t *kr, const hcrypt_algor_t *algor);
hcrypt_prvkey_t *hcrypt_keyring_get0_prvkey_by_name(hcrypt_keyring_t *kr, const char *name);
int hcrypt_keyring_save(hcrypt_keyring_t *kr, FILE *fp);
int hcrypt_keyring_load(hcrypt_keyring_t *kr, FILE *fp);
void hcrypt_keyring_cleanup(hcrypt_keyring_t *kr);


#ifdef __cplusplus
}
#endif
#endif
