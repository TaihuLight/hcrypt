#ifndef HCRYPT_BGN_H
#define HCRYPT_BGN_H

#include "bgn.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef bgn_key_t bgn2_pubkey_t;
typedef bgn_key_t bgn2_prvkey_t;
typedef bgn_plaintext_t bgn2_plaintext_t;

typedef struct {
	const bgn2_pubkey_t *pub_key;
	bgn_ciphertext_t c;
} bgn2_ciphertext_t;


int bgn2_keygen(bgn2_pubkey_t **pk, bgn2_prvkey_t **sk);
int bgn2_encrypt(bgn2_ciphertext_t *c, const bgn2_plaintext_t *m, bgn2_pubkey_t *pk);
int bgn2_decrypt(bgn2_plaintext_t *m, const bgn2_ciphertext_t *c, bgn2_prvkey_t *sk);
int bgn2_ciphertext_add(bgn2_ciphertext_t *c, const bgn2_ciphertext_t *a, const bgn2_ciphertext_t *b, bgn2_pubkey_t *pk);
int bgn2_ciphertext_mul(bgn2_ciphertext_t *c, const bgn2_ciphertext_t *a, const bgn2_ciphertext_t *b, bgn2_pubkey_t *pk);


bgn2_pubkey_t *bgn2_pubkey_new(void);
int bgn2_pubkey_set_str(bgn2_pubkey_t *pk, const char *str);
int bgn2_pubkey_to_str(const bgn2_pubkey_t *pk, char *buf, size_t buflen);
void bgn2_pubkey_free(bgn2_pubkey_t *pk);

bgn2_prvkey_t *bgn2_prvkey_new(void);
int bgn2_prvkey_set_str(bgn2_prvkey_t *sk, const char *str);
int bgn2_prvkey_to_str(const bgn2_prvkey_t *sk, char *buf, size_t buflen);
void bgn2_prvkey_free(bgn2_prvkey_t *sk);

bgn2_plaintext_t *bgn2_plaintext_new(void);
#define bgn2_plaintext_set_word(m,a)	bgn_plaintext_set_word(m,a)
#define bgn2_plaintext_set_str(m,s)	bgn_plaintext_set_str(m,s)
#define bgn2_plaintext_to_word(m,a)	bgn_plaintext_to_word(m,a)
#define bgn2_plaintext_to_str(m,b,l)	bgn_plaintext_to_str(m,b,l)
void bgn2_plaintext_free(bgn2_plaintext_t *m);

bgn2_ciphertext_t *bgn2_ciphertext_new(bgn2_pubkey_t *pk);
int bgn2_ciphertext_set_str(bgn2_ciphertext_t *c, const char *str);
int bgn2_ciphertext_to_str(const bgn2_ciphertext_t *c, char *buf, size_t buflen);
void bgn2_ciphertext_free(bgn2_ciphertext_t *c);


#ifdef __cplusplus
}
#endif
#endif

