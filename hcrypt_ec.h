#ifndef HCRYPT_EC_H
#define HCRYPT_EC_H

#include <openssl/ec.h>
#include <openssl/objects.h>

#ifdef __cplusplus
extern "C" {
#endif


#define EC_CURVE_NAME       NID_X9_62_prime192v1
#define EC_KEY_BITS         192
#define EC_KEY_SIZE         ((EC_KEY_BITS + 7)/8)
#define EC_CIPHERTEXT_SIZE  (EC_KEY_SIZE * 4 + 2)
#define EC_PUBKEY_FORMAT    POINT_CONVERSION_COMPRESSED

#define EC_MAX_PLAINTEXT    1

typedef EC_KEY ec_pubkey_t;
typedef EC_KEY ec_prvkey_t;
typedef BIGNUM ec_plaintext_t;
typedef struct {
	EC_POINT *A;
	EC_POINT *B;
} ec_ciphertext_t;
	
int ec_keygen(ec_pubkey_t **pk, ec_prvkey_t **sk);
int ec_encrypt(ec_ciphertext_t *c, const ec_plaintext_t *m, ec_pubkey_t *pk);
int ec_decrypt(ec_plaintext_t *m, const ec_ciphertext_t *c, ec_prvkey_t *sk);
int ec_ciphertext_add(ec_ciphertext_t *r, const ec_ciphertext_t *a, const ec_ciphertext_t *b, ec_pubkey_t *pk);
int ec_ciphertext_sub(ec_ciphertext_t *r, const ec_ciphertext_t *a, const ec_ciphertext_t *b, ec_pubkey_t *pk);
int ec_ciphertext_neg(ec_ciphertext_t *r, const ec_ciphertext_t *a, ec_pubkey_t *pk);

ec_pubkey_t *ec_pubkey_new(void);
int ec_pubkey_set_str(ec_pubkey_t *pk, const char *str);
int ec_pubkey_to_str(const ec_pubkey_t *pk, char *buf, size_t len);
void ec_pubkey_free(ec_pubkey_t *pk);

ec_prvkey_t *ec_prvkey_new(void);
int ec_prvkey_set_str(ec_prvkey_t *sk, const char *str);
int ec_prvkey_to_str(const ec_prvkey_t *sk, char *buf, size_t len);
void ec_prvkey_free(ec_prvkey_t *sk);

ec_plaintext_t *ec_plaintext_new(void);
int ec_plaintext_set_word(ec_plaintext_t *m, unsigned long a);
int ec_plaintext_to_word(const ec_plaintext_t *m, unsigned long *a);
void ec_plaintext_free(ec_plaintext_t *m);

ec_ciphertext_t *ec_ciphertext_new(void);
int ec_ciphertext_set_str(ec_ciphertext_t *c, const char *str);
int ec_ciphertext_to_str(const ec_ciphertext_t *c, char *buf, size_t len);
void ec_ciphertext_free(ec_ciphertext_t *c);

#ifdef __cplusplus
}
#endif
#endif


