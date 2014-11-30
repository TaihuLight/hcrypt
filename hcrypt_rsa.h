#ifndef HCRYPT_RSA_H
#define HCRYPT_RSA_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct rsa_st rsa_pubkey_t;
typedef struct rsa_st rsa_prvkey_t;
typedef struct bignum_st rsa_plaintext_t;
typedef struct bignum_st rsa_ciphertext_t;


int rsa_keygen(rsa_pubkey_t **pk, rsa_prvkey_t **sk);
int rsa_encrypt(rsa_ciphertext_t *c, const rsa_plaintext_t *m, rsa_pubkey_t *pk);
int rsa_decrypt(rsa_plaintext_t *m, const rsa_ciphertext_t *c, rsa_prvkey_t *sk);
int rsa_ciphertext_mul(rsa_ciphertext_t *r, const rsa_ciphertext_t *a, const rsa_ciphertext_t *b, rsa_pubkey_t *pk);

rsa_pubkey_t *rsa_pubkey_new(void);
int rsa_pubkey_set_str(rsa_pubkey_t *pk, const char *str);
int rsa_pubkey_to_str(const rsa_pubkey_t *pk, char *buf, size_t len);
void rsa_pubkey_free(rsa_pubkey_t *pk);

rsa_prvkey_t *rsa_prvkey_new(void);
int rsa_prvkey_set_str(rsa_prvkey_t *sk, const char *str);
int rsa_prvkey_to_str(const rsa_prvkey_t *sk, char *buf, size_t len);
void rsa_prvkey_free(rsa_prvkey_t *sk);

rsa_plaintext_t *rsa_plaintext_new(void);
int rsa_plaintext_set_word(rsa_plaintext_t *m, unsigned long a);
int rsa_plaintext_to_word(const rsa_plaintext_t *m, unsigned long *a);
void rsa_plaintext_free(rsa_plaintext_t *m);

rsa_ciphertext_t *rsa_ciphertext_new(void);
int rsa_ciphertext_set_str(rsa_ciphertext_t *c, const char *str);
int rsa_ciphertext_to_str(const rsa_ciphertext_t *c, char *buf, size_t len);
void rsa_ciphertext_free(rsa_ciphertext_t *c);




#ifdef __cplusplus
}
#endif
#endif

