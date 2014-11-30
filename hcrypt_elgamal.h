#ifndef HCRYPT_ELGAMAL_H
#define HCRYPT_ELGAMAL_H

#include <openssl/bn.h>
#include <openssl/dsa.h>

#ifdef __cplusplus
extern "C" {
#endif


#define ELGAMAL_KEY_BITS         1024
#define ELGAMAL_KEY_SIZE         ((ELGAMAL_KEY_BITS + 7)/8)
#define ELGAMAL_CIPHERTEXT_SIZE  (ELGAMAL_KEY_SIZE * 4 + 2)


typedef struct dsa_st elgamal_pubkey_t;
typedef struct dsa_st elgamal_prvkey_t;
typedef struct bignum_st elgamal_plaintext_t;
typedef struct {
	BIGNUM *a;
	BIGNUM *b;
} elgamal_ciphertext_t;


int elgamal_keygen(elgamal_pubkey_t **pk, elgamal_prvkey_t **sk);
int elgamal_encrypt(elgamal_ciphertext_t *c, const elgamal_plaintext_t *m, elgamal_pubkey_t *pk);
int elgamal_decrypt(elgamal_plaintext_t *m, const elgamal_ciphertext_t *c, elgamal_prvkey_t *sk);
int elgamal_ciphertext_mul(elgamal_ciphertext_t *r,
	const elgamal_ciphertext_t *a, const elgamal_ciphertext_t *b,
	elgamal_pubkey_t *pk);

elgamal_pubkey_t *elgamal_pubkey_new(void);
int elgamal_pubkey_set_str(elgamal_pubkey_t *pk, const char *str);
int elgamal_pubkey_to_str(const elgamal_pubkey_t *pk, char *buf, size_t len);
void elgamal_pubkey_free(elgamal_pubkey_t *pk);

elgamal_prvkey_t *elgamal_prvkey_new(void);
int elgamal_prvkey_set_str(elgamal_prvkey_t *sk, const char *str);
int elgamal_prvkey_to_str(const elgamal_prvkey_t *sk, char *buf, size_t len);
void elgamal_prvkey_free(elgamal_prvkey_t *sk);

elgamal_plaintext_t *elgamal_plaintext_new(void);
int elgamal_plaintext_set_word(elgamal_plaintext_t *m, unsigned long a);
int elgamal_plaintext_to_word(const elgamal_plaintext_t *m, unsigned long *a);
void elgamal_plaintext_free(elgamal_plaintext_t *m);

elgamal_ciphertext_t *elgamal_ciphertext_new(void);
int elgamal_ciphertext_set_str(elgamal_ciphertext_t *c, const char *str);
int elgamal_ciphertext_to_str(const elgamal_ciphertext_t *c, char *buf, size_t len);
void elgamal_ciphertext_free(elgamal_ciphertext_t *c);


#ifdef __cplusplus
}
#endif
#endif

