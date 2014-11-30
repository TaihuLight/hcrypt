#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "hcrypt.h"
#include "hcrypt_locl.h"

int hcrypt_verbose = 0;
const char *hcrypt_prefix = "hcrypt";

const char *hcrypt_algor_name(const hcrypt_algor_t *algor)
{
	return algor->name;
}

const hcrypt_algor_t *hcrypt_algor_from_name(const char *name)
{
	if (strcmp(name, hcrypt_algor_name(hcrypt_nullint())) == 0)
		return hcrypt_nullint();

	if (strcmp(name, hcrypt_algor_name(hcrypt_nullstr())) == 0)
		return hcrypt_nullstr();

	if (strcmp(name, hcrypt_algor_name(hcrypt_rsa())) == 0)
		return hcrypt_rsa();

	if (strcmp(name, hcrypt_algor_name(hcrypt_elgamal())) == 0)
		return hcrypt_elgamal();

	if (strcmp(name, hcrypt_algor_name(hcrypt_ec())) == 0)
		return hcrypt_ec();

	if (strcmp(name, hcrypt_algor_name(hcrypt_paillier())) == 0)
		return hcrypt_paillier();

	if (strcmp(name, hcrypt_algor_name(hcrypt_bgn())) == 0)
		return hcrypt_bgn();

#if 0
	if (strcmp(name, hcrypt_algor_name(hcrypt_bv())) == 0)
		return hcrypt_bv();

	if (strcmp(name, hcrypt_algor_name(hcrypt_bgv())) == 0)
		return hcrypt_bgv();
#endif

	return NULL;
}


//FIXME: check if library is inited at earch entry

int hcrypt_library_init(void)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	
	return 0;
}

void hcrypt_library_exit(void)
{
	ERR_free_strings();
	EVP_cleanup();
}

int hcrypt_keygen(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk, hcrypt_prvkey_t **sk)
{
	if (!alg || !pk || !sk || *pk || *sk) {
		fprintf(stderr, "hcrypt: %s %d\n", __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT;
	}

	if (alg->keygen == NULL) {
		fprintf(stderr, "hcrypt: %s %d\n", __FILE__, __LINE__);
		return HCRYPT_E_NOT_SUPPORTED;
	}

	return alg->keygen(pk, sk);
}

/*
 * FIXME: the hcrypt_algor_t new/free should be changed to init/cleanup
 * otherwise these functions can not be implemented
 */
#if 0
static int hcrypt_pubkey_change_algor(hcrypt_pubkey_t *pk, const hcrypt_algor_t *alg)
{
	assert(pk && pk->algor);
	assert(alg);
	
	if (pk->algor == alg)
		return 0;

	pk->algor->pubkey_free(pk->u.value);
	pk->algor = alg;
	if (!alg->pubkey_new(pk)) {
		return HCRYPT_E_MALLOC_FAILED;
	}

	return 0;
}

static int hcrypt_prvkey_change_algor(hcrypt_prvkey_t *sk, const hcrypt_algor_t *alg)
{
	assert(sk && sk->algor);
	assert(alg);

	if (sk->algor == alg)
		return 0;

	sk->algor->prvkey_free(sk->u.value);
	
	sk->algor = alg;
	if (!alg->prvkey_new(sk)) {
		return HCRYPT_E_MALLOC_FAILED;
	}

	return 0;
}

static int hcrypt_plaintext_change_algor(hcrypt_plaintext_t *m, const hcrypt_algor_t *alg)
{
	assert(m && m->algor);
	assert(alg);

	if (m->algor == alg)
		return 0;

	m->algor->plaintext_free(m->u.value);
	
	m->algor = alg;
	if (!alg->plaintext_new(m)) {
		return HCRYPT_E_MALLOC_FAILED;
	}

	return 0;
}

static int hcrypt_ciphertext_change_algor(hcrypt_ciphertext_t *c, const hcrypt_algor_t *alg)
{
	assert(c && c->algor);
	assert(alg);

	if (c->algor == alg)
		return 0;

	c->algor->plaintext_free(c->u.value);
	
	c->algor = alg;
	if (!alg->ciphertext_new(c)) {
		return HCRYPT_E_MALLOC_FAILED;
	}

	return 0;
}
#endif

int hcrypt_encrypt(hcrypt_ciphertext_t *ct, const hcrypt_plaintext_t *pt, hcrypt_pubkey_t *pk)
{
//	int r;

	if (!ct || !pt || !pk)
		return HCRYPT_E_INVALID_ARGUMENT;

	if (!pt->algor || !pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT;

	if (pt->algor != pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT;


	if (ct->algor != pk->algor) {
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		if ((r = hcrypt_ciphertext_change_algor(ct, pk->algor)) < 0) {
//			return r;
//		}
	}
	
	return pk->algor->encrypt(ct, pt, pk);
}

int hcrypt_decrypt(hcrypt_plaintext_t *pt, const hcrypt_ciphertext_t *ct, hcrypt_prvkey_t *sk)
{
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!ct || !ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (!sk || !sk->algor)
		return HCRYPT_E_INVALID_ARGUMENT3;

	if (ct->algor != sk->algor)
		return HCRYPT_E_ALGOR_NOT_MATCH;

	if (pt->algor != sk->algor) {
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		int r;
//		if ((r = hcrypt_plaintext_change_algor(pt, sk->algor)) < 0) {
//			return r;
//		}
	}
		
	return sk->algor->decrypt(pt, ct, sk);
}

int hcrypt_ciphertext_add(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b,
	hcrypt_pubkey_t *pk)
{
	if (!r || !r->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT1;
	}

	if (!a || !a->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT2;
	}

	if (!b || !b->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT3;
	}

	if (!pk || !pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT4;
	}

	if (a->algor != pk->algor || b->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
	}

	if (r->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		int r;
//		if ((r = hcrypt_ciphertext_change_algor(r, pk->algor)) < 0) {
//			return r;
//		}
	}		

	if (!pk->algor->add)
		return HCRYPT_E_NOT_SUPPORTED;

	return pk->algor->add(r, a, b, pk);
}

int hcrypt_ciphertext_sub(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b,
	hcrypt_pubkey_t *pk)
{
	if (!r || !r->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT1;
	}

	if (!a || !a->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT2;
	}

	if (!b || !b->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT3;
	}

	if (!pk || !pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT4;
	}

	if (a->algor != pk->algor || b->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
	}

	if (r->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		int r;
//		if ((r = hcrypt_ciphertext_change_algor(r, pk->algor)) < 0) {
//			return r;
//		}
	}		

	if (!pk->algor->sub)
		return HCRYPT_E_NOT_SUPPORTED;

	return pk->algor->sub(r, a, b, pk);
}

int hcrypt_ciphertext_neg(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, hcrypt_pubkey_t *pk)
{
	if (!r || !r->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT1;
	}

	if (!a || !a->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT2;
	}

	if (!pk || !pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT4;
	}

	if (a->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
	}

	if (r->algor != pk->algor) {
		fprintf(stderr, "%s: %s %d\n", __FUNCTION__, __FILE__, __LINE__);
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		int r;
//		if ((r = hcrypt_ciphertext_change_algor(r, pk->algor)) < 0) {
//			return r;
//		}
	}		

	if (!pk->algor->neg)
		return HCRYPT_E_NOT_SUPPORTED;

	return pk->algor->neg(r, a, pk);
}


int hcrypt_ciphertext_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, const hcrypt_ciphertext_t *b,
	hcrypt_pubkey_t *pk)
{
	if (!r || !r->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!a || !a->algor)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (!b || !b->algor)
		return HCRYPT_E_INVALID_ARGUMENT3;

	if (!pk || !pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT4;

	if (a->algor != pk->algor || b->algor != pk->algor)
		return HCRYPT_E_ALGOR_NOT_MATCH;

	if (r->algor != pk->algor) {
		return HCRYPT_E_ALGOR_NOT_MATCH;
//		int r;
//		if ((r = hcrypt_ciphertext_change_algor(r, pk->algor)) < 0) {
//			return r;
//		}
	}		

	if (!pk->algor->mul)
		return HCRYPT_E_NOT_SUPPORTED;

	return pk->algor->mul(r, a, b, pk);
}

int hcrypt_ciphertext_scalar_mul(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k,
	hcrypt_pubkey_t *pk)
{
	return -1;
}

int hcrypt_ciphertext_pow(hcrypt_ciphertext_t *r, const hcrypt_ciphertext_t *a, unsigned int k,
	hcrypt_pubkey_t *pk)
{
	return -1;
}

int hcrypt_pubkey_new(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk)
{
	assert(alg->pubkey_new);

	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!pk)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (*pk) {
		*pk = NULL;
	}

	if (alg->pubkey_new(pk) < 0)
		return HCRYPT_E_MALLOC_FAILED;
	
	assert(*pk);

	return HCRYPT_SUCCESS;
}

int hcrypt_pubkey_new_bin(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk, const unsigned char *buf, size_t len)
{
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!pk)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (*pk) {
		*pk = NULL;
	}

	if (!buf)
		return HCRYPT_E_INVALID_ARGUMENT3;

	
	if (!alg->pubkey_set_bin)
		return HCRYPT_E_NOT_SUPPORTED;

	
	if (alg->pubkey_new(pk) < 0)
		return HCRYPT_E_MALLOC_FAILED;

	assert(*pk);

	return alg->pubkey_set_bin(*pk, buf, len);
}

int hcrypt_pubkey_new_str(const hcrypt_algor_t *alg, hcrypt_pubkey_t **pk, const char *str)
{
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!pk)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (*pk) {
		*pk = NULL;
	}

	if (!str)
		return HCRYPT_E_INVALID_ARGUMENT3;
	
	if (!alg->pubkey_set_str)
		return HCRYPT_E_NOT_SUPPORTED;

	
	if (alg->pubkey_new(pk) < 0)
		return HCRYPT_E_MALLOC_FAILED;

	assert(*pk);

	return alg->pubkey_set_str(*pk, str);
}

int hcrypt_pubkey_to_bin(const hcrypt_pubkey_t *pk, unsigned char *buf, size_t len)
{
	if (!pk || !pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pk->algor->pubkey_to_bin)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pk->algor->pubkey_to_bin(pk, buf, len);
}

int hcrypt_pubkey_to_str(const hcrypt_pubkey_t *pk, char *buf, size_t len)
{
	if (!pk || !pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pk->algor->pubkey_to_str)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pk->algor->pubkey_to_str(pk, buf, len);
}

int hcrypt_pubkey_free(hcrypt_pubkey_t *pk)
{
	if (!pk)
		return 0;
	
	if (!pk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	pk->algor->pubkey_free(pk);

	return 0;
}

int hcrypt_prvkey_new(const hcrypt_algor_t *alg, hcrypt_prvkey_t **sk)
{	
	assert(alg->prvkey_new);
	
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!sk)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (*sk) {
		*sk = NULL;
	}
	
	if (alg->prvkey_new(sk) < 0)
		return HCRYPT_E_MALLOC_FAILED;
	
	assert(*sk);
	
	return HCRYPT_SUCCESS;
}

int hcrypt_prvkey_new_bin(const hcrypt_algor_t *alg, hcrypt_prvkey_t **sk, const unsigned char *buf, size_t len)
{
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!sk)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (*sk) {
		*sk = NULL;
	}

	if (!buf)
		return HCRYPT_E_INVALID_ARGUMENT3;

	
	if (!alg->prvkey_set_bin)
		return HCRYPT_E_NOT_SUPPORTED;

	
	if (alg->prvkey_new(sk) < 0)
		return HCRYPT_E_MALLOC_FAILED;

	assert(*sk);

	return alg->prvkey_set_bin(*sk, buf, len);
	return HCRYPT_E_NOT_SUPPORTED;
}

int hcrypt_prvkey_new_str(const hcrypt_algor_t *alg, hcrypt_prvkey_t **sk, const char *str)
{
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;

	if (!sk)
		return HCRYPT_E_INVALID_ARGUMENT2;

	if (*sk) {
		*sk = NULL;
	}

	if (!str)
		return HCRYPT_E_INVALID_ARGUMENT3;

	
	if (!alg->prvkey_set_str)
		return HCRYPT_E_NOT_SUPPORTED;

	
	if (alg->prvkey_new(sk) < 0)
		return HCRYPT_E_MALLOC_FAILED;

	assert(*sk);

	return alg->prvkey_set_str(*sk, str);
}

int hcrypt_prvkey_to_bin(const hcrypt_prvkey_t *sk, unsigned char *buf, size_t len)
{
	if (!sk || !sk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!sk->algor->pubkey_to_bin)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return sk->algor->prvkey_to_bin(sk, buf, len);
}

int hcrypt_prvkey_to_str(const hcrypt_prvkey_t *sk, char *buf, size_t len)
{
	if (!sk || !sk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!sk->algor->prvkey_to_str)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return sk->algor->prvkey_to_str(sk, buf, len);
}

int hcrypt_prvkey_free(hcrypt_prvkey_t *sk)
{
	if (!sk)
		return 0;
	
	if (!sk->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	sk->algor->prvkey_free(sk);
	
	return 0;
}

int hcrypt_plaintext_new(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt)
{
	assert(alg->plaintext_new);
	
	if (!alg)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pt)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (*pt) {
		*pt = NULL;
	}
	
	if (alg->plaintext_new(pt) < 0)
		return HCRYPT_E_MALLOC_FAILED;
	
	assert(*pt);
	
	return HCRYPT_SUCCESS;
}

int hcrypt_plaintext_new_bin(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, const unsigned char *buf, size_t len)
{
	int r;
	
	if ((r = hcrypt_plaintext_new(alg, pt)) < 0)
		return r;

	assert(*pt);
	
	if ((r = hcrypt_plaintext_set_bin(*pt, buf, len)) < 0)
		return r;
	
	return HCRYPT_SUCCESS;
}

int hcrypt_plaintext_new_str(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, const char *str)
{
	int r;
	
	if ((r = hcrypt_plaintext_new(alg, pt)) < 0)
		return r;

	assert(*pt);	

	if ((r = hcrypt_plaintext_set_str(*pt, str)) < 0)
		return r;
	
	return HCRYPT_SUCCESS;
}

int hcrypt_plaintext_new_dec(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, const char *str)
{
	int a = atoi(str);
	if (a < 0) {
		return HCRYPT_E_INVALID_ARGUMENT3;
	}
	
	return hcrypt_plaintext_new_word(alg, pt, a);
}

int hcrypt_plaintext_new_hex(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, const char *str)
{
	return hcrypt_plaintext_new_str(alg, pt, str);
}

int hcrypt_plaintext_new_word(const hcrypt_algor_t *alg, hcrypt_plaintext_t **pt, unsigned long a)
{
	int r;
	
	if ((r = hcrypt_plaintext_new(alg, pt)) < 0)
		return r;

	assert(*pt);
	
	if ((r = hcrypt_plaintext_set_word(*pt, a)) < 0)
		return r;
	
	return HCRYPT_SUCCESS;
}

int hcrypt_plaintext_set_bin(hcrypt_plaintext_t *pt, const unsigned char *buf, size_t len)
{
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!buf)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (len <= 0)
		return HCRYPT_E_INVALID_ARGUMENT3;
	
	if (pt->algor->plaintext_set_bin == NULL)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pt->algor->plaintext_set_bin(pt, buf, len);
}

int hcrypt_plaintext_set_str(hcrypt_plaintext_t *pt, const char *str)
{
	if (!pt || !pt->algor) {
		fprintf(stderr, "error: %s %s %d\n", __FILE__,  __FUNCTION__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT1;
	}	

	if (!str) {
		fprintf(stderr, "error: %s %s %d\n", __FILE__,  __FUNCTION__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT2;
	}	

	if (strlen(str) <= 0) {
		fprintf(stderr, "error: %s %s %d\n", __FILE__,  __FUNCTION__, __LINE__);
		return HCRYPT_E_INVALID_ARGUMENT3;
	}	

	if (pt->algor->plaintext_set_str == NULL) {
		fprintf(stderr, "error: %s %s %d\n", __FILE__,  __FUNCTION__, __LINE__);
		return HCRYPT_E_NOT_SUPPORTED;
	}
	
	return pt->algor->plaintext_set_str(pt, str);
}

int hcrypt_plaintext_set_dec(hcrypt_plaintext_t *pt, const char *str)
{
	int a = atoi(str);
	if (a < 0)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pt->algor->plaintext_set_word)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pt->algor->plaintext_set_word(pt, a);
}

int hcrypt_plaintext_set_hex(hcrypt_plaintext_t *pt, const char *str)
{
	return hcrypt_plaintext_set_str(pt, str);
}

int hcrypt_plaintext_set_word(hcrypt_plaintext_t *pt, unsigned long a)
{
	assert(pt && pt->algor);

	if (pt->algor->plaintext_set_word == NULL) {
		return HCRYPT_E_NOT_SUPPORTED;
	}

	return pt->algor->plaintext_set_word(pt, a);
}

int hcrypt_plaintext_to_bin(const hcrypt_plaintext_t *pt, unsigned char *buf, size_t len)
{
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pt->algor->plaintext_to_bin)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pt->algor->plaintext_to_bin(pt, buf, len);
}
	
int hcrypt_plaintext_to_str(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!pt->algor->plaintext_to_str)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pt->algor->plaintext_to_str(pt, buf, len);
}

int hcrypt_plaintext_to_dec(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	return -1;
}

int hcrypt_plaintext_to_hex(const hcrypt_plaintext_t *pt, char *buf, size_t len)
{
	return hcrypt_plaintext_to_str(pt, buf, len);
}

int hcrypt_plaintext_to_word(const hcrypt_plaintext_t *pt, unsigned long *a)
{
	if (!pt || !pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!a)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (!pt->algor->plaintext_to_word)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return pt->algor->plaintext_to_word(pt, a);
}

int hcrypt_plaintext_free(hcrypt_plaintext_t *pt)
{
	if (!pt)
		return 0;
	
	if (!pt->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	pt->algor->plaintext_free(pt);
	
	return 0;
}

int hcrypt_ciphertext_new(hcrypt_pubkey_t *pk, hcrypt_ciphertext_t **ct)
{
	assert(pk->algor->ciphertext_new);
	
	if (!pk)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!ct)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (*ct) {
		*ct = NULL;
	}
	
	if (pk->algor->ciphertext_new(ct, pk) < 0)
		return HCRYPT_E_MALLOC_FAILED;
	
	assert(*ct);
	
	return HCRYPT_SUCCESS;
}

int hcrypt_ciphertext_set_bin(hcrypt_ciphertext_t *ct, const unsigned char *buf, size_t len)
{
	if (!ct || !ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!buf)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (len <= 0)
		return HCRYPT_E_INVALID_ARGUMENT3;
	
	if (ct->algor->ciphertext_set_bin == NULL)
		return HCRYPT_E_NOT_SUPPORTED;
	
	
	return ct->algor->ciphertext_set_bin(ct, buf, len);
}

int hcrypt_ciphertext_set_str(hcrypt_ciphertext_t *ct, const char *str)
{
	if (!ct || !ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!str)
		return HCRYPT_E_INVALID_ARGUMENT2;
	
	if (strlen(str) <= 0)
		return HCRYPT_E_INVALID_ARGUMENT3;
	
	if (ct->algor->ciphertext_set_str == NULL)
		return HCRYPT_E_NOT_SUPPORTED;
	
	
	return ct->algor->ciphertext_set_str(ct, str);
}

int hcrypt_ciphertext_new_str(hcrypt_pubkey_t *pk, hcrypt_ciphertext_t **ct, const char *str)
{
	int r;
	
	if ((r = hcrypt_ciphertext_new(pk, ct)) < 0)
		return r;
	
	assert(*ct);	
	
	if ((r = hcrypt_ciphertext_set_str(*ct, str)) < 0)
		return r;
	
	return HCRYPT_SUCCESS;
}

int hcrypt_ciphertext_to_bin(const hcrypt_ciphertext_t *ct, unsigned char *buf, size_t len)
{
	if (!ct || !ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!ct->algor->ciphertext_to_bin)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return ct->algor->ciphertext_to_bin(ct, buf, len);
}

int hcrypt_ciphertext_to_str(const hcrypt_ciphertext_t *ct, char *buf, size_t len)
{
	if (!ct || !ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	if (!ct->algor->ciphertext_to_str)
		return HCRYPT_E_NOT_SUPPORTED;
	
	return ct->algor->ciphertext_to_str(ct, buf, len);
}

int hcrypt_ciphertext_free(hcrypt_ciphertext_t *ct)
{
	if (!ct)
		return 0;
	
	if (!ct->algor)
		return HCRYPT_E_INVALID_ARGUMENT1;
	
	ct->algor->ciphertext_free(ct);
	
	return 0;
}


const hcrypt_algor_t *hcrypt_pubkey_algor(const hcrypt_pubkey_t *pk)
{
	return pk->algor;
}

const hcrypt_algor_t *hcrypt_prvkey_algor(const hcrypt_prvkey_t *sk)
{
	return sk->algor;
}

const hcrypt_algor_t *hcrypt_plaintext_algor(const hcrypt_plaintext_t *pt)
{
	return pt->algor;
}

const hcrypt_algor_t *hcrypt_ciphertext_algor(const hcrypt_ciphertext_t *ct)
{
	return ct->algor;
}
 

