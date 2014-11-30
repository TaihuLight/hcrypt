#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmp.h>
#include <pbc.h>
#include "hcrypt_paillier.h"

int paillier_key_init(paillier_key_t *key)
{
	key->bits = 1024;
	mpz_init(key->n);
	mpz_init(key->lambda);
	mpz_init(key->n_squared);
	mpz_init(key->n_plusone);
	mpz_init(key->x);
	return 0;
}

paillier_key_t *paillier_key_new()
{
	paillier_key_t *ret = NULL;
	if (!(ret = malloc(sizeof(paillier_key_t)))) {
		//fprintf(stderr, "%s: %s\n", __FUNCTION__, strerror(errno));
		return NULL;
	}
	if (paillier_key_init(ret) < 0) {
		fprintf(stderr, "%s: error\n", __FUNCTION__);
		paillier_key_free(ret);
		return NULL;
	}
	return ret;
}

int paillier_key_init_set(paillier_key_t *r, const paillier_key_t *a)
{
	assert(r);
	assert(a);
	
	r->bits = a->bits;
	mpz_init_set(r->n, a->n);
	mpz_init_set(r->lambda, a->lambda);
	mpz_init_set(r->n_squared, a->n_squared);
	mpz_init_set(r->n_plusone, a->n_plusone);
	mpz_init_set(r->x, a->x);
	return 0;
}

int paillier_key_set_str(paillier_key_t *key, const char *str)
{
	char *buf = NULL;
	char *p;
	assert(key);
	assert(str);
	if (!(buf = strdup(str))) {
		fprintf(stderr, "%s: strdup failed at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	if (!(p = strsep(&buf, ":"))) {
		fprintf(stderr, "%s: invalid format `%s' at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		free(buf);
		return -1;
	}
	if (mpz_set_str(key->n, p, 16) < 0) {
		fprintf(stderr, "%s: invalid format `%s' at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		free(buf);
		return -1;
	}
	mpz_mul(key->n_squared, key->n, key->n);
	mpz_add_ui(key->n_plusone, key->n, 1);
	
	if (!(p = strsep(&buf, ":"))) {
		free(buf);
		return 0;
	}
	if (mpz_set_str(key->lambda, p, 16) < 0) {
		fprintf(stderr, "%s: invalid format `%s' at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		free(buf);
		return -1;
	}
	
	free(buf);
	
	mpz_powm(key->x, key->n_plusone, key->lambda, key->n_squared);
	mpz_sub_ui(key->x, key->x, 1);
	mpz_div(key->x, key->x, key->n);
	mpz_invert(key->x, key->x, key->n);	
	
	return 1;
}

int paillier_key_init_set_str(paillier_pubkey_t *key, const char *str)
{
	paillier_key_init(key);
	return paillier_key_set_str(key, str);
}


int paillier_pubkey_set_str(paillier_pubkey_t *pk, const char *str)
{
	return paillier_key_set_str(pk, str);
}

int paillier_pubkey_init_set_str(paillier_pubkey_t *pk, const char *str)
{
	paillier_key_init(pk);
	return paillier_pubkey_set_str(pk, str);
}

int paillier_prvkey_set_str(paillier_pubkey_t *sk, const char *str)
{
	int r = paillier_key_set_str(sk, str);
	if (r < 1) {
		fprintf(stderr, "%s: invalid format `%s' at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		return -1;
	}
	return 1;
}

int paillier_prvkey_init_set_str(paillier_prvkey_t *sk, const char *str)
{
	paillier_key_init(sk);
	return paillier_key_set_str(sk, str);
}

int paillier_pubkey_to_str(const paillier_key_t *key, char *buf, size_t buflen)
{
	int outlen = gmp_snprintf(NULL, 0, "%ZX", key->n) + 1;	
	if (!buf) {
		return outlen;
	}
	if (buflen < outlen) {
		fprintf(stderr, "%s: buffer too small at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	gmp_snprintf(buf, buflen, "%ZX", key->n);
	return outlen;
}

int paillier_prvkey_to_str(const paillier_key_t *key, char *buf, size_t buflen)
{
	int outlen = gmp_snprintf(NULL, 0, "%ZX:%ZX", key->n, key->lambda) + 1;
	if (!buf)
		return outlen;
	if (buflen < outlen) {
		fprintf(stderr, "%s: buffer too small at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	gmp_snprintf(buf, buflen, "%ZX:%ZX", key->n, key->lambda);
 	return outlen;	
}

void paillier_key_cleanup(paillier_key_t *key)
{
	key->bits = 0;
	mpz_clear(key->n);
	mpz_clear(key->lambda);
	mpz_clear(key->n_squared);
	mpz_clear(key->n_plusone);
	mpz_clear(key->x);
	memset(key, 0, sizeof(paillier_key_t));
}

void paillier_key_free(paillier_key_t *key)
{
	paillier_key_cleanup(key);
	free(key);
}

int paillier_key_generate(paillier_key_t *key)
{
	mpz_t p;
	mpz_t q;
	
	do {
		mpz_init(p);
		pbc_mpz_randomb(p, key->bits / 2);
		mpz_nextprime(p, p);
		
		mpz_init(q);
		pbc_mpz_randomb(q, key->bits / 2);
		mpz_nextprime(q, q);
		
		mpz_mul(key->n, p, q);
		
	} while (!mpz_tstbit(key->n, key->bits - 1));

	mpz_sub_ui(p, p, 1);	
	mpz_sub_ui(q, q, 1);
	mpz_lcm(key->lambda, p, q);
	
	mpz_mul(key->n_squared, key->n, key->n);
	mpz_add_ui(key->n_plusone, key->n, 1);
	
	mpz_powm(key->x, key->n_plusone, key->lambda, key->n_squared);
	mpz_sub_ui(key->x, key->x, 1);
	mpz_div(key->x, key->x, key->n);
	mpz_invert(key->x, key->x, key->n);
	
	mpz_clear(p);
	mpz_clear(q);

	return 0;
}

int paillier_keygen(paillier_pubkey_t **pk, paillier_prvkey_t **sk)
{
	int ret = -1;
	paillier_pubkey_t *pubkey = NULL;
	paillier_prvkey_t *prvkey = NULL;

	assert(pk && *pk == NULL);
	assert(sk && *sk == NULL);

	if (!(pubkey = (paillier_pubkey_t *)malloc(sizeof(paillier_pubkey_t)))) {
		fprintf(stderr, "%s: malloc failed at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		goto end;
	}
	if (!(prvkey = (paillier_prvkey_t *)malloc(sizeof(paillier_prvkey_t)))) {
		fprintf(stderr, "%s: malloc failed at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		goto end;
	}

	paillier_key_init(prvkey);
	paillier_key_init(pubkey);

	paillier_key_generate(prvkey);
	mpz_set(pubkey->n, prvkey->n);
	mpz_set(pubkey->n_squared, prvkey->n_squared);
	mpz_set(pubkey->n_plusone, prvkey->n_plusone);

	*pk = pubkey;
	*sk = prvkey;

	ret = 0;

end:
	if (ret < 0) {
		if (pubkey) paillier_pubkey_free(pubkey);
		if (prvkey) paillier_prvkey_free(prvkey);
	}
	
	return ret;
}

int paillier_plaintext_init(paillier_plaintext_t *m)
{
	assert(m);
	mpz_init(m->m);
	return 0;
}

paillier_plaintext_t *paillier_plaintext_new(void)
{
	paillier_plaintext_t *r = NULL;
	if (!(r = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t)))) {
		fprintf(stderr, "%s: malloc failed at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return NULL;
	}
	paillier_plaintext_init(r);
	return r;
}

paillier_ciphertext_t *paillier_ciphertext_new(void)
{
	paillier_ciphertext_t *r = NULL;
	if (!(r = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t)))) {
		fprintf(stderr, "%s: malloc failed at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return NULL;
	}
	paillier_ciphertext_init(r);
	return r;
}

int paillier_plaintext_init_set(paillier_plaintext_t *m, const paillier_plaintext_t *a)
{
	mpz_init_set(m->m, a->m);
	return 0;
}

int paillier_plaintext_set_word(paillier_plaintext_t *m, unsigned long a)
{
	assert(m);
	mpz_set_ui(m->m, a);
	return 0;
}

int paillier_plaintext_init_set_word(paillier_plaintext_t *m, unsigned long a)
{
	assert(m);
	mpz_init_set_ui(m->m, a);
	return 0;
}

int paillier_plaintext_to_word(const paillier_plaintext_t *m, unsigned long *a)
{
	assert(m);
	assert(a);
	// FIXME: check if m->m larger than max value of a
	*a = mpz_get_ui(m->m);
	return 0;
}

int paillier_plaintext_set_dec(paillier_plaintext_t *m, const char *str)
{
	assert(m);
	assert(str);
	assert(strlen(str) > 0);
	if (mpz_set_str(m->m, (char *)str, 10) < 0) {
		fprintf(stderr, "%s: `%s' is not valid dec number at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int paillier_plaintext_init_set_dec(paillier_plaintext_t *m, const char *str)
{
	assert(m);
	assert(str);
	assert(strlen(str) > 0);
	if (mpz_init_set_str(m->m, (char *)str, 10) < 0) {
		fprintf(stderr, "%s: `%s' is not valid dec number at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int paillier_plaintext_to_dec(const paillier_plaintext_t *m, char *buf,
	size_t buflen)
{
	int outlen = gmp_snprintf(NULL, 0, "%ZX", m->m) + 1;
	assert(m);

	if (!buf)
		return outlen;
	if (buflen < outlen) {
		fprintf(stderr, "%s: buffer is too small at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	gmp_snprintf(buf, buflen, "%ZX", m->m);
	return outlen;
}

void paillier_plaintext_cleanup(paillier_plaintext_t *m)
{
	assert(m);
	mpz_clear(m->m);
}

void paillier_plaintext_free(paillier_plaintext_t *m)
{
	paillier_plaintext_cleanup(m);
	free(m);
}

int paillier_ciphertext_init(paillier_ciphertext_t *c)
{
	assert(c);
	mpz_init(c->c);
	return 0;
}

int paillier_ciphertext_init_set(paillier_ciphertext_t *c, const paillier_ciphertext_t *a)
{
	mpz_init_set(c->c, a->c);
	return 0;
}

int paillier_ciphertext_set_zero(paillier_ciphertext_t *c)
{
	mpz_set_ui(c->c, 1);
	return 0;
}

int paillier_ciphertext_set_str(paillier_ciphertext_t *c, const char *str)
{
	assert(c);
	assert(str && strlen(str) > 0);
	if (mpz_set_str(c->c, (char *)str, 16) < 0) {
		fprintf(stderr, "%s: `%s' is not valid hex value at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int paillier_ciphertext_init_set_zero(paillier_ciphertext_t *c)
{
	assert(c);
	mpz_init_set_ui(c->c, 1);
	return 0;
}

int paillier_ciphertext_init_set_str(paillier_ciphertext_t *c, const char *str)
{
	assert(c);
	assert(str && strlen(str) > 0);
	if (mpz_init_set_str(c->c, (char *)str, 16) < 0) {
		fprintf(stderr, "%s: `%s' is not valid hex value at %s %d\n",
			__FUNCTION__, str, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

int paillier_ciphertext_to_str(const paillier_ciphertext_t *c, char *buf,
	size_t buflen)
{
	int outlen = gmp_snprintf(NULL, 0, "%ZX", c->c) + 1;
	if (!buf)
		return outlen;
	if (buflen < outlen) {
		fprintf(stderr, "%s: buffer too small at %s %d\n",
			__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}
	gmp_snprintf(buf, buflen, "%ZX", c->c);
	return outlen;
}

void paillier_ciphertext_cleanup(paillier_ciphertext_t *c)
{
	assert(c);
	mpz_clear(c->c);
}

void paillier_ciphertext_free(paillier_ciphertext_t *c)
{
	paillier_ciphertext_cleanup(c);
	free(c);
}

int paillier_encrypt(paillier_ciphertext_t *c, const paillier_plaintext_t *m,
	paillier_key_t *pk)
{
	mpz_t r;
	mpz_t x;
	
	mpz_init(r);
	do {
		pbc_mpz_randomb(r, 512);
	} while (mpz_cmp(r, pk->n) >= 0);

	mpz_init(x);
	mpz_powm(c->c, pk->n_plusone, m->m, pk->n_squared);
	mpz_powm(x, r, pk->n, pk->n_squared);
	mpz_mul(c->c, c->c, x);
	mpz_mod(c->c, c->c, pk->n_squared);
	
	mpz_clear(x);
	mpz_clear(r);
	
	return 0;
}

int paillier_decrypt(paillier_plaintext_t *m, const paillier_ciphertext_t *c,
	paillier_key_t *sk)
{
	mpz_powm(m->m, c->c, sk->lambda, sk->n_squared);
	mpz_sub_ui(m->m, m->m, 1);
	mpz_div(m->m, m->m, sk->n);
	mpz_mul(m->m, m->m, sk->x);
	mpz_mod(m->m, m->m, sk->n);
	
	return 0;
}

int paillier_ciphertext_add(paillier_ciphertext_t *r,
	const paillier_ciphertext_t *a, const paillier_ciphertext_t *b,
	paillier_key_t *pk)
{
	mpz_mul(r->c, a->c, b->c);
	mpz_mod(r->c, r->c, pk->n_squared);
	return 0;
}

int paillier_ciphertext_scalar_mul(paillier_ciphertext_t *r,
	const paillier_ciphertext_t *a, const paillier_plaintext_t *e,
	paillier_key_t *pk)
{
	mpz_powm(r->c, a->c, e->m, pk->n_squared);
	return 0;
}

