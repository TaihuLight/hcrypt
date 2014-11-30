#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "hcrypt_rsa.h"

int rsa_keygen(rsa_pubkey_t **pk, rsa_prvkey_t **sk)
{
	int ret = -1;

	OPENSSL_assert(pk && *pk == NULL);
	OPENSSL_assert(sk && *sk == NULL);
	
	BIGNUM *e = BN_new();
	RSA *prv_key = RSA_new();
	RSA *pub_key = NULL;

	if (!e || !prv_key) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!BN_set_word(e, 65537)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!RSA_generate_key_ex(prv_key, 1024, e, NULL)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(pub_key = RSAPublicKey_dup(prv_key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	*pk = pub_key;
	*sk = prv_key;

	ret = 0;

end:
	if (e) BN_free(e);
	if (ret && prv_key) RSA_free(prv_key);
	if (ret && pub_key) RSA_free(pub_key);
	
	return ret;
}

int rsa_encrypt(rsa_ciphertext_t *c, const rsa_plaintext_t *m, rsa_pubkey_t *pk)
{
	BN_CTX *ctx = NULL;

	OPENSSL_assert(c);
	OPENSSL_assert(m);
	OPENSSL_assert(pk);

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	OPENSSL_assert(pk->e);
	OPENSSL_assert(pk->n);

	if (!BN_mod_exp(c, m, pk->e, pk->n, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

int rsa_decrypt(rsa_plaintext_t *m, const rsa_ciphertext_t *c, rsa_prvkey_t *sk)
{
	BN_CTX *ctx = BN_CTX_new();

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!BN_mod_exp(m, c, sk->d, sk->n, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

int rsa_ciphertext_mul(rsa_ciphertext_t *r, const rsa_ciphertext_t *a,
	const rsa_ciphertext_t *b, rsa_pubkey_t *pk)
{
	BN_CTX *ctx = BN_CTX_new();

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!BN_mod_mul(r, a, b, pk->n, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

rsa_pubkey_t *rsa_pubkey_new(void)
{
	RSA *rsa = NULL;

	if (!(rsa = RSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	
	return rsa;
}

int rsa_prvkey_to_str(const rsa_prvkey_t *sk, char *buf, size_t len)
{
	int ret = -1;

	char *n = NULL;
	char *e = NULL;
	char *d = NULL;
	unsigned int outlen;

	OPENSSL_assert(sk);
	OPENSSL_assert(sk->n);
	OPENSSL_assert(sk->e);
	OPENSSL_assert(sk->d);

	if (!(n = BN_bn2hex(sk->n))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(e = BN_bn2hex(sk->e))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(d = BN_bn2hex(sk->d))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	outlen = strlen(n) + strlen(e) + strlen(d) + 3;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, n);
	strcat(buf, " ");
	strcat(buf, e);
	strcat(buf, " ");
	strcat(buf, d);
	
	ret = outlen;

end:
	if (n) OPENSSL_free(n);
	if (e) OPENSSL_free(e);
	if (d) OPENSSL_free(d);

	return ret;
}

char *rsa_prvkey_to_new_str(const rsa_prvkey_t *sk)
{
	char *ret = NULL;
	char *n = NULL;
	char *e = NULL;
	char *d = NULL;
	unsigned int len;

	if (!(n = BN_bn2hex(sk->n))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(e = BN_bn2hex(sk->e))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(d = BN_bn2hex(sk->d))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	len = strlen(n) + strlen(e) + strlen(d) + sizeof("  ");
	
	if (!(ret = OPENSSL_malloc(len))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	strcpy(ret, n);
	strcat(ret, " ");
	strcat(ret, e);
	strcat(ret, " ");
	strcat(ret, d);

end:
	if (n) OPENSSL_free(n);
	if (e) OPENSSL_free(e);
	if (d) OPENSSL_free(d);

	return ret;
}

rsa_prvkey_t *rsa_prvkey_new(void)
{
	RSA *sk = NULL;

	if (!(sk = RSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return sk;
}

int rsa_prvkey_set_str(rsa_prvkey_t *sk, const char *str)
{
	char n[1024];
	char e[1024];
	char d[1024];

	OPENSSL_assert(sk);
	OPENSSL_assert(str);

	if (strlen(str) > sizeof(n)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}

	if (sscanf(str, "%s %s %s", n, e, d) != 3) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}

	if (sk->n)
		BN_free(sk->n);

	if (!BN_hex2bn(&sk->n, n)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (sk->e)
		BN_free(sk->e);

	if (!BN_hex2bn(&sk->e, e)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (sk->d)
		BN_free(sk->d);
	
	if (!BN_hex2bn(&sk->d, d)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

rsa_prvkey_t *rsa_prvkey_new_from_str(const char *str)
{
	RSA *rsa = NULL;
	char n_buf[1024];
	char e_buf[1024];
	char d_buf[1024];

	OPENSSL_assert(str);

	if (strlen(str) > sizeof(n_buf)) {
		fprintf(stderr, "invalid data\n");
		return NULL;
	}

	if (sscanf(str, "%s %s %s", n_buf, e_buf, d_buf) != 3) {
		fprintf(stderr, "invalid data\n");
		return NULL;
	}
	
	if (!(rsa = RSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!BN_hex2bn(&rsa->n, n_buf)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}
	
	if (!BN_hex2bn(&rsa->e, e_buf)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}

	if (!BN_hex2bn(&rsa->d, d_buf)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}
	
	if (!RSA_check_key(rsa)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}
		
	return rsa;	
}

int rsa_pubkey_to_str(const rsa_pubkey_t *pk, char *buf, size_t len)
{
	int ret = -1;

	char *n = NULL;
	char *e = NULL;
	unsigned int outlen;

	OPENSSL_assert(pk && pk->n && pk->e);
	
	if (!(n = BN_bn2hex(pk->n))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(e = BN_bn2hex(pk->e))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	outlen = strlen(n) + strlen(e) + sizeof(" ");

	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, n);
	strcat(buf, " ");
	strcat(buf, e);

	ret = outlen;

end:
	if (n) OPENSSL_free(n);
	if (e) OPENSSL_free(e);
	
	return ret;
}

int rsa_pubkey_set_str(rsa_pubkey_t *pk, const char *str)
{
	char n[1024];
	char e[1024];
	
	OPENSSL_assert(pk);
	OPENSSL_assert(str);

	if (strlen(str) > sizeof(n)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}

	if (sscanf(str, "%s %s", n, e) != 2) {
		fprintf(stderr, "invalid foramt\n");
		return -1;
	}

	if (pk->n)
		BN_free(pk->n);
	
	if (!BN_hex2bn(&pk->n, n)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (pk->e)
		BN_free(pk->e);

	if (!BN_hex2bn(&pk->e, e)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

rsa_pubkey_t *rsa_pubkey_new_from_str(const char *str)
{
	RSA *rsa = NULL;	
	char n_buf[1024];
	char e_buf[1024];

	if (strlen(str) > sizeof(n_buf)) {
		fprintf(stderr, "rsa: input stirng to long\n");
		return NULL;
	}

	if (sscanf(str, "%s %s", n_buf, e_buf) != 2) {
		fprintf(stderr, "rsa: input invalid\n");
		return NULL;
	}

	if (!(rsa = RSA_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!BN_hex2bn(&rsa->n, n_buf)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}

	if (!BN_hex2bn(&rsa->e, e_buf)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}

	if (!RSA_check_key(rsa)) {
		ERR_print_errors_fp(stderr);
		RSA_free(rsa);
		return NULL;
	}
	
	return rsa;
}

rsa_plaintext_t *rsa_plaintext_new(void)
{
	BIGNUM *m = NULL;

	if (!(m = BN_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return m;
}

int rsa_plaintext_set_word(rsa_plaintext_t *m, unsigned long a)
{
	OPENSSL_assert(m);
	
	if (!BN_set_word(m, a)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

int rsa_plaintext_to_word(const rsa_plaintext_t *m, unsigned long *a)
{
	OPENSSL_assert(m);
	OPENSSL_assert(a);
	
	*a = BN_get_word(m);
	return 0;
}

rsa_plaintext_t *rsa_plaintext_new_from_word(unsigned int a)
{
	BIGNUM *bn = NULL;

	if (!(bn = BN_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	
	if (!BN_set_word(bn, a)) {
		ERR_print_errors_fp(stderr);
		BN_free(bn);
		return NULL;
	}

	return bn;
}

rsa_plaintext_t *rsa_plaintext_new_from_str(const char *str)
{
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, str)) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return bn;
}


rsa_ciphertext_t *rsa_ciphertext_new(void)
{
	BIGNUM *bn = NULL;

	if (!(bn = BN_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	BN_set_word(bn, 0);

	return bn;
}


int rsa_ciphertext_set_str(rsa_ciphertext_t *c, const char *str)
{
	BIGNUM *bn = NULL;
	
	OPENSSL_assert(c);
	OPENSSL_assert(str);

	if (!BN_hex2bn(&bn, str)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!BN_copy(c, bn)) {
		ERR_print_errors_fp(stderr);
		BN_free(bn);
		return -1;
	}

	BN_free(bn);

	return 0;
}

int rsa_ciphertext_to_str(const rsa_ciphertext_t *c, char *buf, size_t len)
{
	int ret = -1;
	char *str = NULL;
	unsigned int outlen;

	OPENSSL_assert(c);

	if (!(str = BN_bn2hex(c))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	outlen = strlen(str) + 1;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, str);
	
	ret = outlen;
end:
	if (str) OPENSSL_free(str);

	return ret;
}

char *rsa_ciphertext_to_new_str(const rsa_ciphertext_t *c)
{
	char *ret;

	OPENSSL_assert(c);

	if (!(ret = BN_bn2hex(c))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}	
	
	return ret;
}

void rsa_pubkey_free(rsa_pubkey_t *pk)
{
	OPENSSL_assert(pk);
	RSA_free(pk);
}

void rsa_prvkey_free(rsa_prvkey_t *sk)
{
	OPENSSL_assert(sk);
	RSA_free(sk);
}

void rsa_ciphertext_free(rsa_ciphertext_t *c)
{
	OPENSSL_assert(c);
	BN_free(c);
}

void rsa_plaintext_free(rsa_plaintext_t *m)
{
	OPENSSL_assert(m);
	BN_free(m);
}

