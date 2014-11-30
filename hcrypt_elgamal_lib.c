#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "hcrypt_elgamal.h"


int elgamal_keygen(elgamal_pubkey_t **pub_key, elgamal_prvkey_t **prv_key)
{
	int e = 1;
	DSA *sk = NULL;
	DSA *pk = NULL;
	unsigned char seed[20];
	int counter;
	unsigned long h;

	OPENSSL_assert(pub_key && *pub_key == NULL);
	OPENSSL_assert(prv_key && *prv_key == NULL);

	if (!(sk = DSA_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (!RAND_bytes(seed, sizeof(seed))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!DSA_generate_parameters_ex(sk, 1024, seed, sizeof(seed),
		&counter, &h, NULL)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!DSA_generate_key(sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(pk = DSAparams_dup(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(pk->pub_key = BN_dup(sk->pub_key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	e = 0;
end:
	if (e) {
		if (sk) DSA_free(sk);
		if (pk) DSA_free(pk);
		*pub_key = NULL;
		*prv_key = NULL;
		return -1;
	}
	
	*prv_key = sk;
	*pub_key = pk;

	return 0;
}

int elgamal_encrypt(elgamal_ciphertext_t *c, const elgamal_plaintext_t *m,
	elgamal_pubkey_t *pk)
{
	int ret = -1;

	BIGNUM *r = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *a;
	BIGNUM *b;

	const BIGNUM *p = pk->p;
	const BIGNUM *q = pk->q;
	const BIGNUM *g = pk->g;
	const BIGNUM *y = pk->pub_key;

	OPENSSL_assert(c);
	OPENSSL_assert(m);
	OPENSSL_assert(pk);

	OPENSSL_assert(p);
	OPENSSL_assert(q);
	OPENSSL_assert(g);
	OPENSSL_assert(y);

	if (!(r = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (c->a == NULL) {
		if (!(c->a = BN_new())) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}
	a = c->a;
	
	if (c->b == NULL) {
		if (!(c->b = BN_new())) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}
	b = c->b;	

	do {
		if (!BN_rand_range(r, q)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

	} while (BN_is_zero(r));
	
	if (!BN_mod_exp(a, g, r, p, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_mod_exp(b, y, r, p, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_mod_mul(b, b, m, p, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = 0;

end:
	if (r) BN_free(r);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}

int elgamal_decrypt(elgamal_plaintext_t *m, const elgamal_ciphertext_t *c, elgamal_prvkey_t *sk)
{
	BIGNUM *p = sk->p;
	BIGNUM *d = sk->priv_key;
	const BIGNUM *a = c->a;
	const BIGNUM *b = c->b;
	BN_CTX *ctx = NULL;
	
	OPENSSL_assert(m);
	OPENSSL_assert(c);
	OPENSSL_assert(sk);
	OPENSSL_assert(c->a);
	OPENSSL_assert(c->b);
	OPENSSL_assert(sk->p);
	OPENSSL_assert(sk->priv_key);

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!BN_mod_exp(m, a, d, p, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	if (!BN_mod_inverse(m, m, p, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	if (!BN_mod_mul(m, m, b, p, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	return 0;
}

int elgamal_ciphertext_mul(elgamal_ciphertext_t *r,
	const elgamal_ciphertext_t *a, const elgamal_ciphertext_t *b,
	elgamal_pubkey_t *pk)
{
	BN_CTX *ctx = NULL;

	OPENSSL_assert(r);
	OPENSSL_assert(a && a->a && a->b);
	OPENSSL_assert(b && b->a && b->b);
	OPENSSL_assert(pk && pk->p);	

	if (r->a == NULL) {
		if (!(r->a = BN_new())) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	if (r->b == NULL) {
		if (!(r->b = BN_new())) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!BN_mod_mul(r->a, a->a, b->a, pk->p, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);	
		return -1;
	}

	if (!BN_mod_mul(r->b, a->b, b->b, pk->p, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

elgamal_pubkey_t *elgamal_pubkey_new(void)
{
	DSA *dsa = NULL;

	if (!(dsa = DSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return dsa;
}

int elgamal_pubkey_set_str(elgamal_pubkey_t *pk, const char *str)
{
	char p[1024];
	char q[1024];
	char g[1024];
	char pub_key[1024];

	OPENSSL_assert(pk);
	OPENSSL_assert(str);

	if (strlen(str) > sizeof(p)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	if (sscanf(str, "%s %s %s %s", p, q, g, pub_key) != 4) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	if (pk->p)
		BN_free(pk->p);
	
	if (!BN_hex2bn(&pk->p, p)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (pk->q)
		BN_free(pk->q);
	
	if (!BN_hex2bn(&pk->q, q)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (pk->g)
		BN_free(pk->g);
	
	if (!BN_hex2bn(&pk->g, g)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (pk->pub_key)
		BN_free(pk->pub_key);
	
	if (!BN_hex2bn(&pk->pub_key, pub_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	return 0;
}

int elgamal_pubkey_to_str(const elgamal_pubkey_t *pk, char *buf, size_t len)
{
	int ret = -1;

	char *p = NULL;
	char *q = NULL;
	char *g = NULL;
	char *pub_key = NULL;
	unsigned int outlen;

	OPENSSL_assert(pk && pk->p && pk->q && pk->g && pk->pub_key);
	

	if (!(p = BN_bn2hex(pk->p))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(q = BN_bn2hex(pk->q))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(g = BN_bn2hex(pk->g))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(pub_key = BN_bn2hex(pk->pub_key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	outlen = strlen(p) + strlen(q) + strlen(g) + strlen(pub_key) + 4;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, p);
	strcat(buf, " ");
	strcat(buf, q);
	strcat(buf, " ");
	strcat(buf, g);
	strcat(buf, " ");
	strcat(buf, pub_key);

	ret = outlen;

end:
	if (p) OPENSSL_free(p);
	if (q) OPENSSL_free(q);
	if (g) OPENSSL_free(g);
	if (pub_key) OPENSSL_free(pub_key);

	return ret;
}

void elgamal_pubkey_free(elgamal_pubkey_t *pk)
{
	OPENSSL_assert(pk);
	DSA_free(pk);
}

elgamal_prvkey_t *elgamal_prvkey_new(void)
{
	DSA *sk = NULL;

	if (!(sk = DSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return sk;
}

int elgamal_prvkey_set_str(elgamal_prvkey_t *sk, const char *str)
{
	char p[2048];
	char q[2048];
	char g[2048];
	char pub_key[2048];
	char prv_key[2048];
	
	OPENSSL_assert(sk);
	OPENSSL_assert(str);
	
	if (strlen(str) > sizeof(p)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	if (sscanf(str, "%s %s %s %s %s", p, q, g, pub_key, prv_key) != 5) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	if (sk->p)
		BN_free(sk->p);
	
	if (!BN_hex2bn(&sk->p, p)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (sk->q)
		BN_free(sk->q);
	
	if (!BN_hex2bn(&sk->q, q)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (sk->g)
		BN_free(sk->g);
	
	if (!BN_hex2bn(&sk->g, g)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (sk->pub_key)
		BN_free(sk->pub_key);
	
	if (!BN_hex2bn(&sk->pub_key, pub_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (sk->priv_key)
		BN_free(sk->priv_key);
	
	if (!BN_hex2bn(&sk->priv_key, prv_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	return 0;
}

int elgamal_prvkey_to_str(const elgamal_prvkey_t *sk, char *buf, size_t len)
{
	int ret = -1;
	
	char *p = NULL;
	char *q = NULL;
	char *g = NULL;
	char *pub_key = NULL;
	char *prv_key = NULL;
	unsigned int outlen;
	
	OPENSSL_assert(sk);
	OPENSSL_assert(sk->p);
	OPENSSL_assert(sk->q);
	OPENSSL_assert(sk->g);
	OPENSSL_assert(sk->pub_key);
	OPENSSL_assert(sk->priv_key);
	
	if (!(p = BN_bn2hex(sk->p))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(q = BN_bn2hex(sk->q))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(g = BN_bn2hex(sk->g))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(pub_key = BN_bn2hex(sk->pub_key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(prv_key = BN_bn2hex(sk->priv_key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	outlen = strlen(p) + strlen(q) + strlen(g) + strlen(pub_key) + 
		strlen(prv_key) + 5;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}
	
	if (len < outlen) {
		ret = -1;
		goto end;
	}
	
	strcpy(buf, p);
	strcat(buf, " ");
	strcat(buf, q);
	strcat(buf, " ");
	strcat(buf, g);
	strcat(buf, " ");
	strcat(buf, pub_key);
	strcat(buf, " ");
	strcat(buf, prv_key);
	
	ret = outlen;
	
end:
	if (p) OPENSSL_free(p);
	if (q) OPENSSL_free(q);
	if (g) OPENSSL_free(g);
	if (pub_key) OPENSSL_free(pub_key);
	if (prv_key) OPENSSL_free(prv_key);
	
	return ret;	
}

void elgamal_prvkey_free(elgamal_prvkey_t *sk)
{
	OPENSSL_assert(sk);
	DSA_free(sk);
}

elgamal_plaintext_t *elgamal_plaintext_new(void)
{
	BIGNUM *pt = NULL;
	
	if (!(pt = BN_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return pt;
}

int elgamal_plaintext_set_word(elgamal_plaintext_t *m, unsigned long a)
{
	OPENSSL_assert(m);
	
	if (!BN_set_word(m, a)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

int elgamal_plaintext_to_word(const elgamal_plaintext_t *m, unsigned long *a)
{
	OPENSSL_assert(m);
	OPENSSL_assert(a);
	
	*a = BN_get_word(m);
	return 0;
}

void elgamal_plaintext_free(elgamal_plaintext_t *m)
{
	OPENSSL_assert(m);
	BN_free(m);
}

elgamal_ciphertext_t *elgamal_ciphertext_new(void)
{
	elgamal_ciphertext_t *c = NULL;

	if (!(c = OPENSSL_malloc(sizeof(elgamal_ciphertext_t)))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	
	if (!(c->a = BN_new())) {
		OPENSSL_free(c);
		return NULL;
	}

	if (!(c->b = BN_new())) {
		OPENSSL_free(c->a);
		OPENSSL_free(c);
		return NULL;
	}

	return c;
}

int elgamal_ciphertext_set_str(elgamal_ciphertext_t *c, const char *str)
{
	char a[2048];
	char b[2048];

	OPENSSL_assert(c);
	OPENSSL_assert(str);
	
	
	if (strlen(str) > sizeof(a)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	if (sscanf(str, "%s %s", a, b) != 2) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}
	
	/*
	if (c->a) {
		BN_free(c->a);
		c->a = NULL; //FIXME: REMOVE
	}
	*/	

	if (!BN_hex2bn(&(c->a), a)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/*
	if (c->b) {
		BN_free(c->b);
		c->b = NULL;
	}
	*/	
	
	if (!BN_hex2bn(&(c->b), b)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	return 0;
}

int elgamal_ciphertext_to_str(const elgamal_ciphertext_t *c, char *buf, size_t len)
{
	int ret = -1;
	
	char *a = NULL;
	char *b = NULL;
	unsigned int outlen;
	
	OPENSSL_assert(c && c->a && c->b);
	
	if (!(a = BN_bn2hex(c->a))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(b = BN_bn2hex(c->b))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	outlen = strlen(a) + strlen(b) + 2;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}
	
	if (len < outlen) {
		ret = -1;
		goto end;
	}
	
	strcpy(buf, a);
	strcat(buf, " ");
	strcat(buf, b);
	
	ret = outlen;
	
end:
	if (a) OPENSSL_free(a);
	if (b) OPENSSL_free(b);
	
	return ret;
}

void elgamal_ciphertext_free(elgamal_ciphertext_t *c)
{
	if (c->a) BN_free(c->a);
	if (c->b) BN_free(c->b);
	OPENSSL_free(c);
}

