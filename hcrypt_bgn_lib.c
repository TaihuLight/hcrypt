#include <openssl/crypto.h>
#include <openssl/err.h>
#include "hcrypt_bgn.h"
#include "hcrypt_locl.h"

static bgn_key_t *bgn_key_new()
{
	bgn_key_t *key = NULL;
	if (!(key = OPENSSL_malloc(sizeof(bgn_key_t)))) {
		fprintf(stderr, "%s %d: malloc failed\n", __FILE__, __LINE__);
		return NULL;
	}
	return key;
}

static void bgn_key_free(bgn_key_t *key)
{
	OPENSSL_assert(key);
	bgn_key_cleanup(key);
	OPENSSL_free(key);
}

int bgn2_keygen(bgn2_pubkey_t **pk, bgn2_prvkey_t **sk)
{
	int e = 1;
	bgn2_pubkey_t *pub_key = NULL;
	bgn2_prvkey_t *prv_key = NULL;

	OPENSSL_assert(pk && *pk == NULL);
	OPENSSL_assert(sk && *sk == NULL);

	if (!(pub_key = bgn2_pubkey_new())) {
		fprintf(stderr, "%s %d: malloc failed\n", __FILE__, __LINE__);
		goto end;
	}

	if (!(prv_key = bgn2_prvkey_new())) {
		fprintf(stderr, "%s %d: malloc failed\n", __FILE__, __LINE__);
		goto end;
	}

	if (bgn_key_generate(prv_key, 1024) < 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		goto end;
	}
	
	bgn_key_init(pub_key);
	if (bgn_key_init_set(pub_key, prv_key, 0) < 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		goto end;
	}

	e = 0;

end:
	if (e) {
		if (pub_key) bgn2_pubkey_free(pub_key);
		if (prv_key) bgn2_prvkey_free(prv_key);
		*pk = NULL;
		*sk = NULL;
		return -1;
	}
	
	*pk = pub_key;
	*sk = prv_key;

	return 0;
}

int bgn2_encrypt(bgn2_ciphertext_t *c, const bgn2_plaintext_t *m, bgn2_pubkey_t *pk)
{
	c->pub_key = pk;
	
	if (bgn_encrypt(&(c->c), (bgn2_plaintext_t *)m, pk) < 0) {
		fprintf(stderr, "%s (%s %d): error\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	
	return 0;
}

int bgn2_decrypt(bgn2_plaintext_t *m, const bgn2_ciphertext_t *c, bgn2_prvkey_t *sk)
{
	return bgn_decrypt(m, (bgn_ciphertext_t *)&(c->c), sk);
}

int bgn2_ciphertext_add(bgn2_ciphertext_t *c, const bgn2_ciphertext_t *a,
	const bgn2_ciphertext_t *b, bgn2_pubkey_t *pk)
{
	c->pub_key = pk;
	return bgn_ciphertext_add(&(c->c), (bgn_ciphertext_t *)&(a->c), 
		(bgn_ciphertext_t *)&(b->c), pk);
}

int bgn2_ciphertext_mul(bgn2_ciphertext_t *c, const bgn2_ciphertext_t *a,
	const bgn2_ciphertext_t *b, bgn2_pubkey_t *pk)
{
	c->pub_key = pk;
	return bgn_ciphertext_mul(&(c->c), 
		(bgn_ciphertext_t *)&(a->c), 
		(bgn_ciphertext_t *)&(b->c), pk);
}

bgn2_pubkey_t *bgn2_pubkey_new()
{
	return bgn_key_new();
}

int bgn2_pubkey_set_str(bgn2_pubkey_t *pk, const char *str)
{
	bgn_key_init(pk);
	if (bgn_key_init_set_str(pk, str, 0) < 0) {
		fprintf(stderr, "%s %s %d: invalid data\n", __FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int bgn2_pubkey_to_str(const bgn2_pubkey_t *pk, char *buf, size_t buflen)
{
	return bgn_key_to_str((bgn_key_t *)pk, buf, buflen, 0);
}

void bgn2_pubkey_free(bgn2_pubkey_t *pk)
{
	bgn_key_free(pk);
}

bgn2_prvkey_t *bgn2_prvkey_new()
{
	return bgn_key_new();
}

int bgn2_prvkey_set_str(bgn2_prvkey_t *sk, const char *str)
{
	bgn_key_init(sk);
	if (bgn_key_init_set_str(sk, str, 1) < 0) {
		fprintf(stderr, "%s %s %d: invalid data\n", __FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int bgn2_prvkey_to_str(const bgn2_prvkey_t *sk, char *buf, size_t buflen)
{
	return bgn_key_to_str((bgn2_prvkey_t *)sk, buf, buflen, 1);
}

void bgn2_prvkey_free(bgn2_prvkey_t *sk)
{
	bgn_key_free(sk);
}

bgn2_plaintext_t *bgn2_plaintext_new()
{
	bgn_plaintext_t *ret = NULL;
	if (!(ret = OPENSSL_malloc(sizeof(bgn_plaintext_t)))) {
		fprintf(stderr, "%s: malloc failed : %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return NULL;
	}
	bgn_plaintext_init(ret);
	return ret;
}

void bgn2_plaintext_free(bgn2_plaintext_t *m)
{
	OPENSSL_assert(m);
	bgn_plaintext_cleanup(m);
	OPENSSL_free(m);
}

bgn2_ciphertext_t *bgn2_ciphertext_new(bgn2_pubkey_t *pk)
{
	bgn2_ciphertext_t *ret = NULL;

	if (!(ret = OPENSSL_malloc(sizeof(bgn2_ciphertext_t)))) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "%s (%s %d): malloc failed\n",
			__FUNCTION__, __FILE__, __LINE__);
		return NULL;
	}
	
	ret->pub_key = pk;

	if (bgn_ciphertext_init(&(ret->c), 0, pk) < 0) {
		fprintf(stderr, "%s (%s %d): bgn_ciphertext_init() failed\n",
			__FUNCTION__, __FILE__, __LINE__);
		OPENSSL_free(ret);
		return NULL;
	}
	
	return ret;
}

int bgn2_ciphertext_set_str(bgn2_ciphertext_t *c, const char *str)
{
	OPENSSL_assert(c && c->pub_key);
	OPENSSL_assert(str);

	if (bgn_ciphertext_init_set_str(&(c->c), str, (bgn_key_t *)c->pub_key) < 0) {
		fprintf(stderr, "%s (%s %d): init_set_str failed\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

int bgn2_ciphertext_to_str(const bgn2_ciphertext_t *c, char *buf, size_t buflen)
{
	return bgn_ciphertext_to_str((bgn_ciphertext_t *)&(c->c), buf, buflen);	
}

void bgn2_ciphertext_free(bgn2_ciphertext_t *c)
{
	OPENSSL_assert(c);
	bgn_ciphertext_cleanup(&(c->c));
	OPENSSL_free(c);
}

