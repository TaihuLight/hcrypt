#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "hcrypt.h"
#include "hcrypt_locl.h"

static int mod_keygen(hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk)
{
	OPENSSL_assert(pk && *pk == NULL);
	OPENSSL_assert(sk && *sk == NULL);

	if (!(*pk = OPENSSL_malloc(sizeof(hcrypt_pubkey_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(*sk = OPENSSL_malloc(sizeof(hcrypt_prvkey_t)))) {
		ERR_print_errors_fp(stderr);
		OPENSSL_free(*pk);
		*pk = NULL;
		return -1;
	}

	(*pk)->algor = hcrypt_nullstr();
	(*sk)->algor = hcrypt_nullstr();
	(*pk)->u.word = 0;
	(*sk)->u.word = 0;
	
	return 0;
}

static int mod_encrypt(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt,
	hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(ct && pt && pk);
	OPENSSL_assert(ct->algor == hcrypt_nullstr());
	OPENSSL_assert(pk->algor == hcrypt_nullstr());
	OPENSSL_assert(pt->algor == hcrypt_nullstr());
	OPENSSL_assert(pt->u.str);
	OPENSSL_assert(strlen(pt->u.str) > 0);

	if (ct->u.str) {
		OPENSSL_free(ct->u.str);
		ct->u.str = NULL;
	}

	if (!(ct->u.str = OPENSSL_malloc(strlen(pt->u.str) + 1))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	strcpy(ct->u.str, pt->u.str);
	
	return 0;
}

static int mod_decrypt(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct,
	hcrypt_prvkey_t *sk)
{
	OPENSSL_assert(pt && ct && sk);
	OPENSSL_assert(pt->algor == hcrypt_nullstr());
	OPENSSL_assert(ct->algor == hcrypt_nullstr());
	OPENSSL_assert(sk->algor == hcrypt_nullstr());
	OPENSSL_assert(ct->u.str);

	if (pt->u.str) {
		OPENSSL_free(pt->u.str);
		pt->u.str = NULL;
	}

	if (!(pt->u.str = OPENSSL_malloc(strlen(ct->u.str) + 1))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	strcpy(pt->u.str, ct->u.str);
	
	return 0;
}

static int mod_ciphertext_add(hcrypt_ciphertext_t *r,
	const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b,
	hcrypt_pubkey_t *pk)
{
	char *rstr = NULL;

	OPENSSL_assert(r && a && b && pk);
	OPENSSL_assert(r->algor == hcrypt_nullstr());
	OPENSSL_assert(a->algor == hcrypt_nullstr());
	OPENSSL_assert(b->algor == hcrypt_nullstr());
	OPENSSL_assert(pk->algor == hcrypt_nullstr());
	OPENSSL_assert(a->u.str);
	OPENSSL_assert(b->u.str);

	if (!(rstr = OPENSSL_malloc(strlen(a->u.str) + strlen(b->u.str) + 1))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}	

	strcpy(rstr, a->u.str);
	strcat(rstr, b->u.str);

	if (r->u.str) {
		OPENSSL_free(r->u.str);
		r->u.str = NULL;
	}

	r->u.str = rstr;
	
	return 0;
}

#if 0
static int mod_ciphertext_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return -1;
}
#endif

#if 0
static int mod_ciphertext_scalar_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	unsigned int k, hcrypt_pubkey_t *pk)
{
	return -1;
}
#endif

#if 0
static int mod_ciphertext_pow(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	unsigned int k, hcrypt_pubkey_t *pk)
{
	return -1;
}
#endif

static int mod_pubkey_new(hcrypt_pubkey_t **pk)
{
	OPENSSL_assert(pk);
	OPENSSL_assert(*pk == NULL);

	if (!(*pk = OPENSSL_malloc(sizeof(hcrypt_pubkey_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	(*pk)->algor = hcrypt_nullstr();
	(*pk)->u.word = 0;

	return 0;
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
	OPENSSL_assert(pk && str);
	OPENSSL_assert(pk->algor == hcrypt_nullstr());

	return 0;	
}

static int mod_pubkey_to_str(const hcrypt_pubkey_t *pk, char *buf, size_t len)
{
	OPENSSL_assert(pk);
	OPENSSL_assert(pk->algor == hcrypt_nullstr());

	if (buf == NULL)
		return sizeof("0");
	
	if (len < sizeof("0"))
		return -1;

	strcpy(buf, "0");
	
	return sizeof("0");
}

static int mod_pubkey_free(hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(pk);
	OPENSSL_assert(pk->algor == hcrypt_nullstr());

	OPENSSL_free(pk);
	return 0;
}

static int mod_prvkey_new(hcrypt_prvkey_t **sk)
{
	OPENSSL_assert(sk);
	OPENSSL_assert(*sk == NULL);

	if (!(*sk = OPENSSL_malloc(sizeof(hcrypt_prvkey_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	(*sk)->algor = hcrypt_nullstr();
	(*sk)->u.word = 0;

	return 0;
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
	OPENSSL_assert(sk && str);
	OPENSSL_assert(sk->algor == hcrypt_nullstr());

	sk->u.word = 0;
	return 0;
}

static int mod_prvkey_to_str(const hcrypt_prvkey_t *sk, char *buf, size_t len)
{
	OPENSSL_assert(sk);
	OPENSSL_assert(sk->algor == hcrypt_nullstr());

	if (buf == NULL)
		return sizeof("0");
	
	if (len < sizeof("0"))
		return -1;

	strcpy(buf, "0");
	
	return sizeof("0");
}

static int mod_prvkey_free(hcrypt_prvkey_t *sk)
{
	OPENSSL_assert(sk);
	OPENSSL_assert(sk->algor = hcrypt_nullstr());

	OPENSSL_free(sk);
	return 0;
}

static int mod_plaintext_new(hcrypt_plaintext_t **pt)
{
	OPENSSL_assert(pt && *pt == NULL);

	if (!(*pt = OPENSSL_malloc(sizeof(hcrypt_plaintext_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	(*pt)->algor = hcrypt_nullstr();
	(*pt)->u.str = NULL;
	
	return 0;
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

static int mod_plaintext_set_str(hcrypt_plaintext_t *pt, const char *str)
{
	OPENSSL_assert(pt && str);
	OPENSSL_assert(pt->algor == hcrypt_nullstr());
	
	if (pt->u.str) {
		OPENSSL_free(pt->u.str);
		pt->u.str = NULL;
	}

	if (!(pt->u.str = OPENSSL_malloc(strlen(str) + 1))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	strcpy(pt->u.str, str);
	return 0;
}

static int mod_plaintext_to_str(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	OPENSSL_assert(pt && pt->algor == hcrypt_nullstr());
	OPENSSL_assert(pt->u.str);	

	if (buf == NULL)
		return strlen(pt->u.str) + 1;

	if (len < strlen(pt->u.str) + 1)
		return -1;

	strcpy(buf, pt->u.str);
	return strlen(pt->u.str) + 1;
}

#if 0
static int mod_plaintext_set_word(hcrypt_plaintext_t *pt, unsigned long a)
{
	OPENSSL_assert(pt);
	OPENSSL_assert(pt->algor = hcrypt_ecies());
	OPENSSL_assert(pt->u.ecies);

	return ecies_plaintext_set_word(pt->u.ecies, a);
}

static int mod_plaintext_to_word(const hcrypt_plaintext_t *pt, unsigned long *a)
{
	OPENSSL_assert(pt && a);
	OPENSSL_assert(pt->algor == hcrypt_ecies());
	OPENSSL_assert(pt->u.ecies);

	return ecies_plaintext_to_word(pt->u.ecies, a);
}
#endif

static int mod_plaintext_free(hcrypt_plaintext_t *pt)
{
	OPENSSL_assert(pt);
	OPENSSL_assert(pt->algor == hcrypt_nullstr());
	
	if (pt->u.str) {
		OPENSSL_free(pt->u.str);
		pt->u.str = NULL;
	}

	OPENSSL_free(pt);
	return 0;
}

static int mod_ciphertext_new(hcrypt_ciphertext_t **ct, hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(ct);
	OPENSSL_assert(*ct == NULL);

	if (!(*ct = OPENSSL_malloc(sizeof(hcrypt_ciphertext_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	(*ct)->algor = hcrypt_nullstr();
	(*ct)->u.str = NULL;

	return 0;
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
	OPENSSL_assert(ct && str);
	OPENSSL_assert(ct->algor == hcrypt_nullstr());

	if (ct->u.str) {
		OPENSSL_free(ct->u.str);
		ct->u.str = NULL;
	}

	if (!(ct->u.str = OPENSSL_malloc(strlen(str) + 1))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	strcpy(ct->u.str, str);

	return 0;
}

static int mod_ciphertext_to_str(const hcrypt_ciphertext_t *ct, char *buf, size_t len)
{
	OPENSSL_assert(ct && ct->algor == hcrypt_nullstr());
	OPENSSL_assert(ct->u.str);

	if (buf == NULL)
		return strlen(ct->u.str) + 1;

	if (len < strlen(ct->u.str) + 1)
		return -1;


	strcpy(buf, ct->u.str);
	return strlen(ct->u.str) + 1;
}

static int mod_ciphertext_free(hcrypt_ciphertext_t *ct)
{
	OPENSSL_assert(ct);
	OPENSSL_assert(ct->algor == hcrypt_nullstr());
	
	if (ct->u.str) {
		OPENSSL_free(ct->u.str);
		ct->u.str = NULL;
	}

	OPENSSL_free(ct);
	return 0;
}



static const hcrypt_algor_t nullstr_algor = {
	"nullstr",
	mod_keygen, /* keygen */
	mod_encrypt, /* encrypt */
	mod_decrypt, /* decrypt */
	mod_ciphertext_add, /* add */
	NULL, /* sub */
	NULL, /* neg */
	NULL, /* mul */
	NULL, /* scalar_mul */
	NULL, /* pow */
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
	NULL, /* plaintext_set_word */
	NULL, /* plaintext_to_word */
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

const hcrypt_algor_t *hcrypt_nullstr(void)
{
	return (&nullstr_algor);
}

