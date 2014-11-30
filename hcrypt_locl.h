#ifndef HEADER_HCRYPT_LOCL_H
#define HEADER_HCRYPT_LOCL_H

#include <stdint.h>
#include <string.h>
#include <gmp.h>
#include <openssl/dsa.h>
#include "hcrypt.h"
#include "hcrypt_rsa.h"
#include "hcrypt_elgamal.h"
#include "hcrypt_ec.h"
#include "hcrypt_paillier.h"
#include "hcrypt_bgn.h"
#include "hcrypt_bv.h"
#include "hcrypt_bgv.h"

#ifdef __cplusplus
extern "C" {
#endif




struct hcrypt_pubkey_t {
	const hcrypt_algor_t *algor;
	union {
		void *value;
		uint32_t word;
		char *str;
		rsa_pubkey_t *rsa;
		elgamal_pubkey_t *elgamal;
		ec_pubkey_t *ec;
		paillier_pubkey_t *paillier;
		bgn2_pubkey_t *bgn;
		bv_pubkey_t *bv;
		bgv_pubkey_t *bgv;
	} u;
};

struct hcrypt_prvkey_t {
	const hcrypt_algor_t *algor;
	union {
		void *value;
		uint32_t word;
		char *str;
		rsa_prvkey_t *rsa;
		elgamal_prvkey_t *elgamal;
		ec_prvkey_t *ec;
		paillier_prvkey_t *paillier;
		bgn2_prvkey_t *bgn;
		bv_prvkey_t *bv;
		bgv_prvkey_t *bgv;
	} u;
};

struct hcrypt_plaintext_t {
	const hcrypt_algor_t *algor;
	union {
		void *value;
		uint32_t word;
		char *str;
		rsa_plaintext_t *rsa;
		elgamal_plaintext_t *elgamal;
		ec_plaintext_t *ec;
		paillier_plaintext_t *paillier;
		bgn2_plaintext_t *bgn;
		bv_plaintext_t *bv;
		bgv_plaintext_t *bgv;
	} u;
};

struct hcrypt_ciphertext_t {
	const hcrypt_algor_t *algor;
	union {
		void *value;
		uint32_t word;
		char *str;
		rsa_ciphertext_t *rsa;
		elgamal_ciphertext_t *elgamal;
		ec_ciphertext_t *ec;
		paillier_ciphertext_t *paillier;
		bgn2_ciphertext_t *bgn;
		bv_ciphertext_t *bv;
		bgv_ciphertext_t *bgv;
	} u;
};

struct hcrypt_algor_t {
	/* module name */
	char *name;

	/* common crypto operations */
	int (*keygen)(hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk);
	int (*encrypt)(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt, hcrypt_pubkey_t *pk);
	int (*decrypt)(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct, hcrypt_prvkey_t *sk);

	/* homomorphic opertaions */
	int (*add)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);
	int (*sub)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);	
	int (*neg)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, hcrypt_pubkey_t *pk);
	int (*mul)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk);
	int (*scalar_mul)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k, hcrypt_pubkey_t *pk);
	int (*pow)(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k, hcrypt_pubkey_t *pk);

	/* public key operations */
	int (*pubkey_new)(hcrypt_pubkey_t **pk);
	int (*pubkey_set_bin)(hcrypt_pubkey_t *pk, const unsigned char *buf, size_t len);
	int (*pubkey_to_bin)(const hcrypt_pubkey_t *pk, unsigned char *buf, size_t len);
	int (*pubkey_set_str)(hcrypt_pubkey_t *pk, const char *str);
	int (*pubkey_to_str)(const hcrypt_pubkey_t *pk, char *buf, size_t len);
	int (*pubkey_free)(hcrypt_pubkey_t *pk);

	/* private key operations */
	int (*prvkey_new)(hcrypt_prvkey_t **sk);
	int (*prvkey_set_bin)(hcrypt_prvkey_t *sk, const unsigned char *buf, size_t len);
	int (*prvkey_to_bin)(const hcrypt_prvkey_t *sk, unsigned char *buf, size_t len);
	int (*prvkey_set_str)(hcrypt_prvkey_t *sk, const char *str);
	int (*prvkey_to_str)(const hcrypt_prvkey_t *sk, char *buf, size_t len);
	int (*prvkey_free)(hcrypt_prvkey_t *sk);

	/* plaintext operations */
	int (*plaintext_new)(hcrypt_plaintext_t **pt); // some times plaintext init also requires public params, to get the range of plaintext value
	int (*plaintext_set_bin)(hcrypt_plaintext_t *pt, const unsigned char *buf, size_t len);
	int (*plaintext_to_bin)(const hcrypt_plaintext_t *pt, unsigned char *buf, size_t len);
	int (*plaintext_set_word)(hcrypt_plaintext_t *pt, unsigned long a);
	int (*plaintext_to_word)(const hcrypt_plaintext_t *pt, unsigned long *a);
	int (*plaintext_set_str)(hcrypt_plaintext_t *pk, const char *str);
	int (*plaintext_to_str)(const hcrypt_plaintext_t *pt, char *buf, size_t len);
	int (*plaintext_free)(hcrypt_plaintext_t *pt);

	/* ciphertext operations */
	int (*ciphertext_new)(hcrypt_ciphertext_t **ct, hcrypt_pubkey_t *pk); //FIXME: init ciphertext requires public key in many cryptosystems.
	int (*ciphertext_set_bin)(hcrypt_ciphertext_t *ct, const unsigned char *buf, size_t len);
	int (*ciphertext_to_bin)(const hcrypt_ciphertext_t *ct, unsigned char *buf, size_t len);
	int (*ciphertext_set_str)(hcrypt_ciphertext_t *ct, const char *str);
	int (*ciphertext_to_str)(const hcrypt_ciphertext_t *ct, char *buf, size_t len);
	int (*ciphertext_free)(hcrypt_ciphertext_t *ct);
};


#ifdef __cplusplus
}
#endif
#endif
