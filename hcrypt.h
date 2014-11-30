#ifndef HEADER_HCRYPT_H
#define HEADER_HCRYPT_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif



int hcrypt_library_init(void);
void hcrypt_library_exit(void);


typedef struct hcrypt_algor_t hcrypt_algor_t;



const hcrypt_algor_t *hcrypt_ec(void);
const hcrypt_algor_t *hcrypt_rsa(void);
const hcrypt_algor_t *hcrypt_bgn(void);
const hcrypt_algor_t *hcrypt_ecies(void);
const hcrypt_algor_t *hcrypt_elgamal(void);
const hcrypt_algor_t *hcrypt_nullint(void);
const hcrypt_algor_t *hcrypt_nullstr(void);
const hcrypt_algor_t *hcrypt_paillier(void);

const char *hcrypt_algor_name(const hcrypt_algor_t *algor);
const hcrypt_algor_t *hcrypt_algor_from_name(const char *name);


typedef struct hcrypt_pubkey_t hcrypt_pubkey_t;
typedef struct hcrypt_prvkey_t hcrypt_prvkey_t;
typedef struct hcrypt_plaintext_t hcrypt_plaintext_t;
typedef struct hcrypt_ciphertext_t hcrypt_ciphertext_t;


int hcrypt_keygen(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk);
int hcrypt_encrypt(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt, hcrypt_pubkey_t *pk);
int hcrypt_decrypt(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct, hcrypt_prvkey_t *sk);

int hcrypt_ciphertext_add(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);
int hcrypt_ciphertext_sub(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);
int hcrypt_ciphertext_neg(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, hcrypt_pubkey_t *pk);
int hcrypt_ciphertext_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);
int hcrypt_ciphertext_scalar_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k, hcrypt_pubkey_t *pk);
int hcrypt_ciphertext_pow(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k, hcrypt_pubkey_t *pk);

int hcrypt_pubkey_new(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk);
int hcrypt_pubkey_new_str(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk, const char *str);
int hcrypt_pubkey_set_str(hcrypt_pubkey_t *pk, const char *str);
int hcrypt_pubkey_to_str(const hcrypt_pubkey_t *pk, char *buf, size_t len);
int hcrypt_pubkey_free(hcrypt_pubkey_t *pk);

int hcrypt_prvkey_new(const hcrypt_algor_t *alg, hcrypt_prvkey_t **sk);
int hcrypt_prvkey_new_str(const hcrypt_algor_t *alg, hcrypt_prvkey_t **sk, const char *str);
int hcrypt_prvkey_set_str(hcrypt_prvkey_t *sk, const char *str);
int hcrypt_prvkey_to_str(const hcrypt_prvkey_t *sk, char *buf, size_t len);
int hcrypt_prvkey_free(hcrypt_prvkey_t *sk);

int hcrypt_plaintext_new(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt);
int hcrypt_plaintext_set_str(hcrypt_plaintext_t *pt, const char *str);
int hcrypt_plaintext_new_str(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, const char *str);
int hcrypt_plaintext_new_word(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, unsigned long a);
int hcrypt_plaintext_set_bin(hcrypt_plaintext_t *pt, const unsigned char *buf, size_t len);
int hcrypt_laintext_set_str(hcrypt_plaintext_t *pt, const char *str);
int hcrypt_plaintext_set_word(hcrypt_plaintext_t *pt, unsigned long a);
int hcrypt_plaintext_to_str(const hcrypt_plaintext_t *pt, char *buf, size_t len);
int hcrypt_plaintext_to_word(const hcrypt_plaintext_t *pt, unsigned long *a);
int hcrypt_plaintext_free(hcrypt_plaintext_t *pt);

int hcrypt_ciphertext_new(hcrypt_pubkey_t *pk, hcrypt_ciphertext_t **ct);
int hcrypt_ciphertext_set_str(hcrypt_ciphertext_t *ct, const char *str);
int hcrypt_ciphertext_new_str(hcrypt_pubkey_t *pk, hcrypt_ciphertext_t **ct, const char *str);
int hcrypt_ciphertext_to_str(const hcrypt_ciphertext_t *ct, char *buf, size_t len);
int hcrypt_ciphertext_free(hcrypt_ciphertext_t *ct);

const hcrypt_algor_t *hcrypt_pubkey_algor(const hcrypt_pubkey_t *pk);
const hcrypt_algor_t *hcrypt_prvkey_algor(const hcrypt_prvkey_t *sk);
const hcrypt_algor_t *hcrypt_plaintext_algor(const hcrypt_plaintext_t *pt);
const hcrypt_algor_t *hcrypt_ciphertext_algor(const hcrypt_ciphertext_t *ct);

#define hcrypt_pubkey_algor_name(pk)	hcrypt_algor_name(hcrypt_pubkey_algor(pk))
#define hcrypt_prvkey_algor_name(sk)	hcrypt_algor_name(hcrypt_prvkey_algor(sk))
#define hcrypt_plaintext_algor_name(pt)	hcrypt_algor_name(hcrypt_plaintext_algor(pt))
#define hcrypt_ciphertext_algor_name(ct) hcrypt_algor_name(hcrypt_ciphertext_algor(ct))

const char *hcrypt_errmsg(int err_code);

#define HCRYPT_SUCCESS			 0		
#define HCRYPT_E_INVALID_ARGUMENT	-1
#define HCRYPT_E_MALLOC_FAILURE		-2
#define HCRYPT_E_MALLOC_FAILED		-2
#define HCRYPT_E_UNKNOWN		-3
#define HCRYPT_E_NOT_SUPPORTED		-4
#define HCRYPT_E_INVALID_DATA		-5
#define HCRYPT_E_INVALID_ARGUMENT1	-11
#define HCRYPT_E_INVALID_ARGUMENT2	-12
#define HCRYPT_E_INVALID_ARGUMENT3	-13
#define HCRYPT_E_INVALID_ARGUMENT4	-14
#define HCRYPT_E_INVALID_ARGUMENT5	-15
#define HCRYPT_E_ALGOR_NOT_MATCH	-21

#ifdef __cplusplus
}
#endif
#endif
