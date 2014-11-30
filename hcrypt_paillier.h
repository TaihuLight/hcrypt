#ifndef HCRYPT_PAILLIER_H
#define HCRYPT_PAILLIER_H

#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	int bits;
	mpz_t n;	 /* public key */
	mpz_t lambda;	 /* private key, lambda(n) = lcm(p-1, q-1) */
	mpz_t n_squared; /* online */
	mpz_t n_plusone; /* online */
	mpz_t x;	 /* online */
} paillier_key_t;

typedef paillier_key_t paillier_pubkey_t;
typedef paillier_key_t paillier_prvkey_t;

typedef struct {
	mpz_t m;
} paillier_plaintext_t;

typedef struct {
	mpz_t c;
} paillier_ciphertext_t;


int paillier_key_init(paillier_key_t *key);
int paillier_key_set_str(paillier_key_t *key, const char *str);
int paillier_key_init_set_str(paillier_pubkey_t *key, const char *str);
int paillier_pubkey_set_str(paillier_pubkey_t *pk, const char *str);
int paillier_pubkey_init_set_str(paillier_pubkey_t *pk, const char *str);
int paillier_prvkey_set_str(paillier_pubkey_t *sk, const char *str);
int paillier_prvkey_init_set_str(paillier_prvkey_t *sk, const char *str);
int paillier_pubkey_to_str(const paillier_key_t *key, char *buf, size_t buflen);
int paillier_prvkey_to_str(const paillier_key_t *key, char *buf, size_t buflen);
void paillier_key_cleanup(paillier_key_t *key);


paillier_key_t *paillier_key_new(void);
#define paillier_pubkey_new()	paillier_key_new()
#define paillier_prvkey_new()	paillier_key_new()
void paillier_key_free(paillier_key_t *key);
#define paillier_pubkey_free(k)	paillier_key_free(k)
#define paillier_prvkey_free(k) paillier_key_free(k)

int paillier_key_generate(paillier_key_t *key);
int paillier_keygen(paillier_pubkey_t **pk, paillier_prvkey_t **sk);
paillier_plaintext_t *paillier_plaintext_new(void);
int paillier_plaintext_init(paillier_plaintext_t *m);
int paillier_plaintext_set_word(paillier_plaintext_t *m, unsigned long a);
int paillier_plaintext_init_set_word(paillier_plaintext_t *m, unsigned long a);
int paillier_plaintext_to_word(const paillier_plaintext_t *m, unsigned long *a);
int paillier_plaintext_set_dec(paillier_plaintext_t *m, const char *str);
int paillier_plaintext_init_set_dec(paillier_plaintext_t *m, const char *str);
int paillier_plaintext_to_dec(const paillier_plaintext_t *m, char *buf, size_t buflen);
void paillier_plaintext_cleanup(paillier_plaintext_t *m);
void paillier_plaintext_free(paillier_plaintext_t *m);
paillier_ciphertext_t *paillier_ciphertext_new(void);
int paillier_ciphertext_init(paillier_ciphertext_t *c);
int paillier_ciphertext_set_zero(paillier_ciphertext_t *c);
int paillier_ciphertext_set_str(paillier_ciphertext_t *c, const char *str);
int paillier_ciphertext_init_set_zero(paillier_ciphertext_t *c);
int paillier_ciphertext_init_set_str(paillier_ciphertext_t *c, const char *str);
int paillier_ciphertext_to_str(const paillier_ciphertext_t *c, char *buf, size_t buflen);
void paillier_ciphertext_cleanup(paillier_ciphertext_t *c);
void paillier_ciphertext_free(paillier_ciphertext_t *c);
int paillier_encrypt(paillier_ciphertext_t *c, const paillier_plaintext_t *m, paillier_key_t *pk);
int paillier_decrypt(paillier_plaintext_t *m, const paillier_ciphertext_t *c, paillier_key_t *sk);
int paillier_ciphertext_add(paillier_ciphertext_t *r,
	const paillier_ciphertext_t *a, const paillier_ciphertext_t *b,
	paillier_key_t *pk);
int paillier_ciphertext_scalar_mull(paillier_ciphertext_t *r,
	const paillier_ciphertext_t *a, const paillier_plaintext_t *e,
	paillier_key_t *pk);


#ifdef __cplusplus
}
#endif
#endif
