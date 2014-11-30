#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "hcrypt.h"
#include "hcrypt_locl.h"
#include "hcrypt_elgamal.h"


static int mod_keygen(hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk)
{
	elgamal_pubkey_t *pub_key = NULL;
	elgamal_prvkey_t *prv_key = NULL;

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

	if (elgamal_keygen(&pub_key, &prv_key) < 0) {
		OPENSSL_free(*pk);
		OPENSSL_free(*sk);
		*pk = NULL;
		*sk = NULL;
		return -1;
	}

	(*pk)->algor = hcrypt_elgamal();
	(*sk)->algor = hcrypt_elgamal();
	(*pk)->u.elgamal = pub_key;
	(*sk)->u.elgamal = prv_key;
	
	return 0;
}

static int mod_encrypt(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt,
	hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(ct && pt && pk);
	OPENSSL_assert(ct->algor == hcrypt_elgamal());
	OPENSSL_assert(pk->algor == hcrypt_elgamal());
	OPENSSL_assert(pt->algor == hcrypt_elgamal());
	OPENSSL_assert(ct->u.elgamal);
	OPENSSL_assert(pt->u.elgamal);
	OPENSSL_assert(pk->u.elgamal);

	if (elgamal_encrypt(ct->u.elgamal, pt->u.elgamal, pk->u.elgamal) < 0) {
		fprintf(stderr, "encrypt failed\n");
		return -1;
	}

	return 0;
}

static int mod_decrypt(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct,
	hcrypt_prvkey_t *sk)
{
	OPENSSL_assert(pt && ct && sk);
	OPENSSL_assert(pt->algor == hcrypt_elgamal());
	OPENSSL_assert(ct->algor == hcrypt_elgamal());
	OPENSSL_assert(sk->algor == hcrypt_elgamal());
	OPENSSL_assert(pt->u.elgamal);
	OPENSSL_assert(ct->u.elgamal);
	OPENSSL_assert(sk->u.elgamal);

	if (elgamal_decrypt(pt->u.elgamal, ct->u.elgamal, sk->u.elgamal) < 0) {
		fprintf(stderr, "decrypt failed\n");
		return -1;
	}

	return 0;
}

#if 0
static int mod_ciphertext_add(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return -1;
}
#endif

static int mod_ciphertext_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a,
	const hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(r && a && b && pk);
	OPENSSL_assert(r->algor == hcrypt_elgamal());
	OPENSSL_assert(a->algor == hcrypt_elgamal());
	OPENSSL_assert(b->algor == hcrypt_elgamal());
	OPENSSL_assert(pk->algor == hcrypt_elgamal());
	OPENSSL_assert(r->u.elgamal);
	OPENSSL_assert(a->u.elgamal);
	OPENSSL_assert(b->u.elgamal);
	OPENSSL_assert(pk->u.elgamal);
	
	if (elgamal_ciphertext_mul(r->u.elgamal, a->u.elgamal,
		b->u.elgamal, pk->u.elgamal) < 0) {
		fprintf(stderr, "add failed\n");
		return -1;
	}

	return 0;
}

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
	elgamal_pubkey_t *pub_key = NULL;
	
	OPENSSL_assert(pk);
	OPENSSL_assert(*pk == NULL);

	if (!(*pk = OPENSSL_malloc(sizeof(hcrypt_pubkey_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(pub_key = elgamal_pubkey_new())) {
		OPENSSL_free(*pk);
		*pk = NULL;
		return -1;
	}

	(*pk)->algor = hcrypt_elgamal();
	(*pk)->u.elgamal = pub_key;

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
	OPENSSL_assert(pk->algor == hcrypt_elgamal());
	OPENSSL_assert(pk->u.elgamal);

	return elgamal_pubkey_set_str(pk->u.elgamal, str);
}

static int mod_pubkey_to_str(const hcrypt_pubkey_t *pk, char *buf, size_t len)
{
	OPENSSL_assert(pk);
	OPENSSL_assert(pk->algor == hcrypt_elgamal());
	OPENSSL_assert(pk->u.elgamal);

	return elgamal_pubkey_to_str(pk->u.elgamal, buf, len);
}

static int mod_pubkey_free(hcrypt_pubkey_t *pk)
{
	OPENSSL_assert(pk);
	OPENSSL_assert(pk->algor == hcrypt_elgamal());

	if (pk->u.elgamal) {
		elgamal_pubkey_free(pk->u.elgamal);
	}

	OPENSSL_free(pk);

	return 0;
}

static int mod_prvkey_new(hcrypt_prvkey_t **sk)
{
	elgamal_prvkey_t *prv_key = NULL;
	
	OPENSSL_assert(sk);
	OPENSSL_assert(*sk == NULL);

	if (!(*sk = OPENSSL_malloc(sizeof(hcrypt_prvkey_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(prv_key = elgamal_prvkey_new())) {
		OPENSSL_free(*sk);
		*sk = NULL;
		return -1;
	}

	(*sk)->algor = hcrypt_elgamal();
	(*sk)->u.elgamal = prv_key;

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
	OPENSSL_assert(sk->algor == hcrypt_elgamal());
	OPENSSL_assert(sk->u.elgamal);

	return elgamal_prvkey_set_str(sk->u.elgamal, str);
}

static int mod_prvkey_to_str(const hcrypt_prvkey_t *sk, char *buf, size_t len)
{
	OPENSSL_assert(sk);
	OPENSSL_assert(sk->algor == hcrypt_elgamal());
	OPENSSL_assert(sk->u.elgamal);

	return elgamal_prvkey_to_str(sk->u.elgamal, buf, len);
}

static int mod_prvkey_free(hcrypt_prvkey_t *sk)
{
	OPENSSL_assert(sk);
	OPENSSL_assert(sk->algor = hcrypt_elgamal());

	if (sk->u.elgamal) {
		elgamal_prvkey_free(sk->u.elgamal);
	}

	OPENSSL_free(sk);

	return 0;
}

static int mod_plaintext_new(hcrypt_plaintext_t **pt)
{
	elgamal_plaintext_t *m = NULL;

	OPENSSL_assert(pt);
	OPENSSL_assert(*pt == NULL);

	if (!(*pt = OPENSSL_malloc(sizeof(hcrypt_plaintext_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(m = elgamal_plaintext_new())) {
		OPENSSL_free(*pt);
		*pt = NULL;
		return -1;
	}

	(*pt)->algor = hcrypt_elgamal();
	(*pt)->u.elgamal = m;
	
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
	unsigned long a;
	OPENSSL_assert(pt);
	OPENSSL_assert(pt->algor == hcrypt_elgamal());
	OPENSSL_assert(pt->u.elgamal);

 	a = atoi(str);
	return elgamal_plaintext_set_word(pt->u.elgamal, a);
}

static int mod_plaintext_to_str(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	unsigned long a;
	int outlen;

	if (elgamal_plaintext_to_word(pt->u.elgamal, &a) < 0) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		return -1;
	}

	outlen = snprintf(NULL, 0, "%lu", a) + 1;
	
	if (buf == NULL)
		return outlen;

	if (len < outlen)
		return -1;

	snprintf(buf, len, "%lu", a);
	return outlen;
}

static int mod_plaintext_set_word(hcrypt_plaintext_t *pt, unsigned long a)
{
	OPENSSL_assert(pt);
	OPENSSL_assert(pt->algor = hcrypt_elgamal());
	OPENSSL_assert(pt->u.elgamal);

	return elgamal_plaintext_set_word(pt->u.elgamal, a);
}

static int mod_plaintext_to_word(const hcrypt_plaintext_t *pt, unsigned long *a)
{
	OPENSSL_assert(pt && a);
	OPENSSL_assert(pt->algor == hcrypt_elgamal());
	OPENSSL_assert(pt->u.elgamal);

	return elgamal_plaintext_to_word(pt->u.elgamal, a);
}

static int mod_plaintext_free(hcrypt_plaintext_t *pt)
{
	OPENSSL_assert(pt);
	OPENSSL_assert(pt->algor == hcrypt_elgamal());
	
	if (pt->u.elgamal) {
		elgamal_plaintext_free(pt->u.elgamal);
	}

	OPENSSL_free(pt);

	return 0;
}

static int mod_ciphertext_new(hcrypt_ciphertext_t **ct, hcrypt_pubkey_t *pk)
{
	elgamal_ciphertext_t *c = NULL;

	OPENSSL_assert(ct);
	OPENSSL_assert(*ct == NULL);

	if (!(*ct = OPENSSL_malloc(sizeof(hcrypt_ciphertext_t)))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(c = elgamal_ciphertext_new())) {
		OPENSSL_free(*ct);
		*ct = NULL;
		return -1;
	}

	(*ct)->algor = hcrypt_elgamal();
	(*ct)->u.elgamal = c;

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
	OPENSSL_assert(ct->algor == hcrypt_elgamal());
	OPENSSL_assert(ct->u.elgamal);

	return elgamal_ciphertext_set_str(ct->u.elgamal, str);
}

static int mod_ciphertext_to_str(const hcrypt_ciphertext_t *ct, char *buf, size_t len)
{
	OPENSSL_assert(ct);
	OPENSSL_assert(ct->algor == hcrypt_elgamal());
	OPENSSL_assert(ct->u.elgamal);

	return elgamal_ciphertext_to_str(ct->u.elgamal, buf, len);
}

static int mod_ciphertext_free(hcrypt_ciphertext_t *ct)
{
	OPENSSL_assert(ct);
	OPENSSL_assert(ct->algor == hcrypt_elgamal());
	
	if (ct->u.elgamal) {
		elgamal_ciphertext_free(ct->u.elgamal);
	}

	OPENSSL_free(ct);
	return 0;
}



static const hcrypt_algor_t elgamal_algor = {
	"elgamal",
	mod_keygen, /* keygen */
	mod_encrypt, /* encrypt */
	mod_decrypt, /* decrypt */
	NULL, /* add */
	NULL, /* sub */
	NULL, /* neg */
	mod_ciphertext_mul, /* mul */
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
	mod_plaintext_set_word, /* plaintext_set_word */
	mod_plaintext_to_word, /* plaintext_to_word */
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

const hcrypt_algor_t *hcrypt_elgamal(void)
{
	return (&elgamal_algor);
}

