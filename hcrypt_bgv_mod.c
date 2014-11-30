#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hcrypt.h"
#include "hcrypt_locl.h"

static int mod_keygen(hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk)
{
	return -1;
}

static int mod_encrypt(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt,
	hcrypt_pubkey_t *pk)
{
	return -1;
}

static int mod_decrypt(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct,
	hcrypt_prvkey_t *sk)
{
	return -1;
}

static int mod_ciphertext_add(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return -1;
}

static int mod_ciphertext_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return -1;
}

static int mod_ciphertext_scalar_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	unsigned int k, hcrypt_pubkey_t *pk)
{
	return -1;
}

static int mod_ciphertext_pow(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	unsigned int k, hcrypt_pubkey_t *pk)
{
	return -1;
}

static int mod_pubkey_new(hcrypt_pubkey_t **pk)
{
	return -1;
}

#if 0
static int mod_pubkey_set_bin(hcrypt_pubkey_t *pk, const unsigned char *buf, size_t len)
{
	return -1;
}

static int mod_pubkey_to_bin(const hcrypt_pubkey_t *pk, unsigned char *buf, size_t len)
{
	return -1;
}
#endif

static int mod_pubkey_set_str(hcrypt_pubkey_t *pk, const char *str)
{
	return -1;
}

static int mod_pubkey_to_str(const hcrypt_pubkey_t *pk, char *buf, size_t len)
{
	return -1;
}

static int mod_pubkey_free(hcrypt_pubkey_t *pk)
{
	return -1;
}


static int mod_prvkey_new(hcrypt_prvkey_t **sk)
{
	return -1;
}

#if 0
static int mod_prvkey_set_bin(hcrypt_prvkey_t *sk, const unsigned char *buf, size_t len)
{
	return -1;
}

static int mod_prvkey_to_bin(const hcrypt_prvkey_t *sk, unsigned char *buf, size_t len)
{
	return -1;
}
#endif

static int mod_prvkey_set_str(hcrypt_prvkey_t *sk, const char *str)
{
	return -1;
}

static int mod_prvkey_to_str(const hcrypt_prvkey_t *sk, char *buf, size_t len)
{
	return -1;
}

static int mod_prvkey_free(hcrypt_prvkey_t *sk)
{
	return -1;
}

static int mod_plaintext_new(hcrypt_plaintext_t **pt)
{
	return -1;
}

#if 0
static int mod_plaintext_set_bin(hcrypt_plaintext_t *pt,
	const unsigned char *buf, size_t len)
{
	return -1;
}

static int mod_plaintext_to_bin(const hcrypt_plaintext_t *pt,
	unsigned char *buf, size_t len)
{
	return -1;
}
#endif

static int mod_plaintext_set_str(hcrypt_plaintext_t *pk, const char *str)
{
	return -1;
}

static int mod_plaintext_to_str(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	return -1;
}

static int mod_plaintext_free(hcrypt_plaintext_t *pt)
{
	return -1;
}

static int mod_ciphertext_new(hcrypt_ciphertext_t **ct)
{
	return -1;
}

#if 0
static int mod_ciphertext_set_bin(hcrypt_ciphertext_t *ct, const unsigned char *buf, size_t len)
{
	return -1;
}

static int mod_ciphertext_to_bin(const hcrypt_ciphertext_t *ct, unsigned char *buf, size_t len)
{
	return -1;
}
#endif

static int mod_ciphertext_set_str(hcrypt_ciphertext_t *ct, const char *str)
{
	return -1;
}

static int mod_ciphertext_to_str(const hcrypt_ciphertext_t *ct, char *buf, size_t len)
{
	return -1;
}

static int mod_ciphertext_free(hcrypt_ciphertext_t *ct)
{
	return -1;
}

static const hcrypt_algor_t bgv_algor = {
	"bgv",
	mod_keygen, /* keygen */
	mod_encrypt, /* encrypt */
	mod_decrypt, /* decrypt */
	mod_ciphertext_add, /* add */
	mod_ciphertext_mul, /* mul */
	mod_ciphertext_scalar_mul, /* scalar_mul */
	mod_ciphertext_pow, /* pow */
	mod_pubkey_new, /* pubkey_new */
	NULL, /* pubkey_set_bin */
	NULL, /* pubkey_to_bin */
	mod_pubkey_set_str, /* pubkey_set_str */
	mod_pubkey_to_str, /* pubkey_to_str */
	mod_pubkey_free, /* pubkey_free */
	mod_prvkey_new, /* prvkey_new */
	NULL, /* prvkey_set_bin */
	NULL, /* prvkey_to_bin */
	mod_prvkey_set_str, /* prvkey_set_str */
	mod_prvkey_to_str, /* prvkey_to_str */
	mod_prvkey_free, /* prvkey_free */
	mod_plaintext_new, /* plaintext_new */
	NULL, /* plaintext_set_bin */
	NULL, /* plaintext_to_bin */
	NULL,
	NULL,
	mod_plaintext_set_str, /* plaintext_set_str */
	mod_plaintext_to_str, /* plaintext_to_str */
	mod_plaintext_free, /* plaintext_free */
	mod_ciphertext_new, /* ciphertext_new */
	NULL, /* ciphertext_set_bin */
	NULL, /* ciphertext_to_bin */
	mod_ciphertext_set_str, /* ciphertext_set_str */
	mod_ciphertext_to_str, /* ciphertext_to_str */
	mod_ciphertext_free, /* ciphertext_free */
};

const hcrypt_algor_t *hcrypt_bgv(void)
{
	return (&bgv_algor);
}


