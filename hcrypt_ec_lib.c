#include <string.h>
#include <openssl/err.h>
#include "hcrypt_ec.h"

int ec_keygen(ec_pubkey_t **pk, ec_prvkey_t **sk)
{
	EC_KEY *prv_key = NULL;
	EC_KEY *pub_key = NULL;

	OPENSSL_assert(pk && *pk == NULL);
	OPENSSL_assert(sk && *sk == NULL);

	if (!(prv_key = EC_KEY_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!EC_KEY_generate_key(prv_key)) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(prv_key);
		return -1;
	}

	if (!(pub_key = EC_KEY_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(prv_key);
		return -1;
	}

	if(!EC_KEY_set_public_key(pub_key, EC_KEY_get0_public_key(prv_key))) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(prv_key);
		EC_KEY_free(pub_key);
		return -1;
	}

	*pk = pub_key;
	*sk = prv_key;

	return 0;
}

int ec_encrypt(ec_ciphertext_t *c, const ec_plaintext_t *m, ec_pubkey_t *pk)
{
	int ret = -1;
	const EC_GROUP *group;
	const EC_POINT *point;	
	BIGNUM *order = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *r = NULL;


	OPENSSL_assert(c);
	OPENSSL_assert(m);
	OPENSSL_assert(pk);


	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(order = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_GROUP_get_order(group, order, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(r = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	do {
		if (!BN_rand_range(r, order)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

	} while (BN_is_zero(r));

	if (c->A == NULL) {
		if (!(c->A = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}

	/* c->A = [r]G */
	if (!EC_POINT_mul(group, c->A, r, NULL, NULL, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (c->B == NULL) {
		if (!(c->B = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}

	if (!(point = EC_KEY_get0_public_key(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	{
		//EC_POINT *T = EC_POINT_new(group);
		//EC_POINT_mul(group, T, m, NULL, NULL, ctx);
		//printf("[m]G = %s\n", EC_POINT_point2hex(group, T, EC_PUBKEY_FORMAT, ctx));		
	}

	/* c->b = [m]G + [r]P */
	if (!EC_POINT_mul(group, c->B, m, point, r, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = 0;

end:
	if (r) BN_free(r);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}

/* A == [r]G
 * B == [m]G + [r]P == [m]G + [rd]G
 * B - [d]A == B - [rd]G == [m]G
 */
int ec_decrypt(ec_plaintext_t *m, const ec_ciphertext_t *c, ec_prvkey_t *sk)
{
	int ret = -1;

	const EC_GROUP *group;
	const EC_POINT *G;
	const BIGNUM *d;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point2 = NULL;
	unsigned int i;

	OPENSSL_assert(m);
	OPENSSL_assert(c && c->A && c->B);
	OPENSSL_assert(sk);

	if (!(group = EC_KEY_get0_group(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(G = EC_GROUP_get0_generator(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(d = EC_KEY_get0_private_key(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(order = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_GROUP_get_order(group, order, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(point = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_one(order)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = [d]A = [rd]G */
	if (!EC_POINT_mul(group, point, NULL, c->A, d, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = -[rd]G */
	if (!EC_POINT_invert(group, point, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = B - [rd]G = [m]G + [rd]G - [rd]G = [m]G */
	if (!EC_POINT_add(group, point, point, c->B, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	{
		//printf("[m]G = %s\n", EC_POINT_point2hex(group, point, EC_PUBKEY_FORMAT, ctx));
	}

	if (!(point2 = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_POINT_set_to_infinity(group, point2)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	for (i = 0; i < EC_MAX_PLAINTEXT; i++) {
		
		//printf("%03d ", i);
		//printf("     %s\n", EC_POINT_point2hex(group, point, EC_PUBKEY_FORMAT, ctx));
		//printf("     %s\n", EC_POINT_point2hex(group, point2, EC_PUBKEY_FORMAT, ctx));		

		if (EC_POINT_cmp(group, point, point2, ctx) == 0) {
			if (!BN_set_word(m, i)) {
				ERR_print_errors_fp(stderr);
				goto end;
			}
			
			//printf("SUCCESS: %d\n", i+1);	
			ret = 0;
			goto end;
		}

		EC_POINT_add(group, point2, point2, EC_GROUP_get0_generator(group), ctx);
	}


end:
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (point) EC_POINT_free(point);
	if (point2) EC_POINT_free(point2);

	return ret;
}

int ec_ciphertext_add(ec_ciphertext_t *r,
	const ec_ciphertext_t *a, const ec_ciphertext_t *b,
	ec_pubkey_t *pk)
{
	const EC_GROUP *group = EC_KEY_get0_group(pk);
	BN_CTX *ctx = NULL;

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	OPENSSL_assert(a->A);
	OPENSSL_assert(b->A);
	OPENSSL_assert(a->B);
	OPENSSL_assert(b->B);

	if (r->A == NULL) {
		if (!(r->A = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	if (r->B == NULL) {
		if (!(r->B = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}
	
	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (!EC_POINT_add(group, r->A, a->A, b->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}


	if (!EC_POINT_add(group, r->B, a->B, b->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);
	
	return 0;
}

int ec_ciphertext_sub(ec_ciphertext_t *r,
	const ec_ciphertext_t *a, const ec_ciphertext_t *b,
	ec_pubkey_t *pk)
{
	const EC_GROUP *group = EC_KEY_get0_group(pk);
	BN_CTX *ctx = NULL;

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	OPENSSL_assert(a->A);
	OPENSSL_assert(b->A);
	OPENSSL_assert(a->B);
	OPENSSL_assert(b->B);

	if (ec_ciphertext_neg(r, b, pk) < 0) {
		fprintf(stderr, "%s (%s %d): ec_ciphertext_neg failed\n",
		__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}

	
	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (!EC_POINT_add(group, r->A, r->A, a->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	if (!EC_POINT_add(group, r->B, r->B, a->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);
	
	return 0;
}

int ec_ciphertext_neg(ec_ciphertext_t *r, const ec_ciphertext_t *a,
	ec_pubkey_t *pk)
{
	const EC_GROUP *group;
	BN_CTX *ctx = NULL;

	OPENSSL_assert(r && a && pk);
	OPENSSL_assert(a->A);
	OPENSSL_assert(a->B);


	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (r->A)
		EC_POINT_free(r->A);
	if (!(r->A = EC_POINT_dup(a->A, group))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (r->B)
		EC_POINT_free(r->B);
	if (!(r->B = EC_POINT_dup(a->B, group))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (!EC_POINT_invert(group, r->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}
	if (!EC_POINT_invert(group, r->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}


	BN_CTX_free(ctx);
	
	return 0;
}

ec_pubkey_t *ec_pubkey_new(void)
{
	EC_KEY *ret = NULL;

	if (!(ret = EC_KEY_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ret;
}

void ec_pubkey_free(ec_pubkey_t *pk)
{
	OPENSSL_assert(pk);
	EC_KEY_free(pk);
}

int ec_pubkey_set_str(ec_pubkey_t *pk, const char *str)
{
	const EC_GROUP *group;
	BN_CTX *ctx = NULL;
	EC_POINT *point = NULL;

	OPENSSL_assert(pk);
	OPENSSL_assert(str);

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(point = EC_POINT_hex2point(group, str, NULL, ctx))) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}
	
	if (!EC_KEY_set_public_key(pk, point)) {
		ERR_print_errors_fp(stderr);
		EC_POINT_free(point);
		BN_CTX_free(ctx);
		return -1;
	}

	EC_POINT_free(point);
	BN_CTX_free(ctx);

	return 0;
}

ec_pubkey_t *ec_pubkey_new_from_str(const char *str)
{
	EC_KEY *ret = NULL;
	BN_CTX *ctx = NULL;
	EC_POINT *point = NULL;
	EC_GROUP *group = NULL;

	if (!(group = EC_GROUP_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(point = EC_POINT_hex2point(group, str, NULL, ctx))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(ret = EC_KEY_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_KEY_set_public_key(ret, point)) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ret);
		ret = NULL;
		goto end;
	}

end:
	if (ctx) BN_CTX_free(ctx);
	if (point) EC_POINT_free(point);
	if (group) EC_GROUP_free(group);
	
	return ret;	
}

int ec_pubkey_to_str(const ec_pubkey_t *pk, char *buf, size_t len)
{
	int ret = -1;

	const EC_GROUP *group;
	const EC_POINT *point;
	BN_CTX *ctx = NULL;
	char *p = NULL;
	unsigned int outlen;


	if(!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(point = EC_KEY_get0_public_key(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(p = EC_POINT_point2hex(group, point, EC_PUBKEY_FORMAT, ctx))) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		goto end;
	}

	outlen = strlen(p) + 1;
	
	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, p);

	ret = outlen;

end:
	if (ctx) BN_CTX_free(ctx);
	if (p) OPENSSL_free(p);	

	return ret;
}

ec_prvkey_t *ec_prvkey_new(void)
{
	EC_KEY *ec_key = NULL;

	if (!(ec_key = EC_KEY_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ec_key;
}


int ec_prvkey_set_str(ec_prvkey_t *sk, const char *str)
{	
	BIGNUM *bn = NULL;

	OPENSSL_assert(sk);
	OPENSSL_assert(str);

	if (!BN_hex2bn(&bn, str)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!EC_KEY_set_private_key(sk, bn)) {
		ERR_print_errors_fp(stderr);
		BN_free(bn);
		return -1;
	}

	return 0;
}

int ec_prvkey_to_str(const ec_prvkey_t *sk, char *buf, size_t len)
{
	int ret = -1;
	const BIGNUM *bn;
	char *p = NULL;
	unsigned int outlen;

	OPENSSL_assert(sk);

	if (!(bn = EC_KEY_get0_private_key(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(p = BN_bn2hex(bn))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	outlen = strlen(p) + 1;

	if (buf == NULL) {
		ret = outlen;
		goto end;
	}

	if (len < outlen) {
		ret = -1;
		goto end;
	}

	strcpy(buf, p);

	ret = outlen;

end:
	if (p) OPENSSL_free(p);

	return ret;
}

void ec_prvkey_free(ec_prvkey_t *sk)
{
	OPENSSL_assert(sk);
	EC_KEY_free(sk);
}

ec_plaintext_t *ec_plaintext_new(void)
{
	BIGNUM *ret;

	if (!(ret = BN_new())) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ret;
}

void ec_plaintext_free(ec_plaintext_t *m)
{
	OPENSSL_assert(m);
	BN_free(m);
}

int ec_plaintext_set_word(ec_plaintext_t *m, unsigned long a)
{
	OPENSSL_assert(m);

	if (!BN_set_word(m, a)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

int ec_plaintext_to_word(const ec_plaintext_t *m, unsigned long *a)
{
	OPENSSL_assert(m);
	OPENSSL_assert(a);

	*a = BN_get_word(m);
	return 0;
}

ec_ciphertext_t *ec_ciphertext_new(void)
{
	ec_ciphertext_t *c = NULL;
	EC_GROUP *group = NULL;

	if (!(group = EC_GROUP_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!(c = OPENSSL_malloc(sizeof(ec_ciphertext_t)))) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		return NULL;
	}

	if (!(c->A = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		OPENSSL_free(c);
		return NULL;
	}

	if (!(c->B = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		EC_POINT_free(c->A);
		EC_GROUP_free(group);
		OPENSSL_free(c);
		return NULL;
	}

	EC_GROUP_free(group);
	return c;
}

void ec_ciphertext_free(ec_ciphertext_t *c)
{
	OPENSSL_assert(c);

	if (c->A) EC_POINT_free(c->A);
	if (c->B) EC_POINT_free(c->B);

	OPENSSL_free(c);
}

int ec_ciphertext_set_str(ec_ciphertext_t *c, const char *str)
{
	char A[1024];
	char B[1024];
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	
	OPENSSL_assert(c);
	OPENSSL_assert(str);

	if (strlen(str) > sizeof(A)) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}

	if (sscanf(str, "%s %s", A, B) != 2) {
		fprintf(stderr, "invalid data\n");
		return -1;
	}

	{
		//printf("%s %d: %s %s\n", __FILE__, __LINE__, A, B);
	}

	/*
	if (c->A) {
		EC_POINT_free(c->A);
		c->A = NULL;
	}

	if (c->B) {
		EC_POINT_free(c->B);
		c->B = NULL;
	}
	*/

	if (!(group = EC_GROUP_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		return -1;
	}
	
	if (!EC_POINT_hex2point(group, A, c->A, ctx)) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		BN_CTX_free(ctx);
		return -1;
	}

	if (!EC_POINT_hex2point(group, B, c->B, ctx)) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		BN_CTX_free(ctx);
		EC_POINT_free(c->A);
		c->A = NULL;
		return -1;
	}

	OPENSSL_assert(c->A);
	OPENSSL_assert(c->B);

	EC_GROUP_free(group);
	BN_CTX_free(ctx);

	return 0;
}


int ec_ciphertext_to_str(const ec_ciphertext_t *c, char *buf, size_t len)
{
	int ret = -1;

	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	char *A = NULL;
	char *B = NULL;
	unsigned int outlen;
	
	OPENSSL_assert(c);


	if (!(group = EC_GROUP_new_by_curve_name(EC_CURVE_NAME))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	OPENSSL_assert(c->A);
	if (!(A = EC_POINT_point2hex(group, c->A, EC_PUBKEY_FORMAT, ctx))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	OPENSSL_assert(c->B);
	if (!(B = EC_POINT_point2hex(group, c->B, EC_PUBKEY_FORMAT, ctx))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	outlen = strlen(A) + strlen(B) + sizeof(" ");
	
	if (!buf) {
		ret = (int)outlen;
		goto end;
	}

	if (len < outlen) {
		fprintf(stderr, "ec: output buf is not long enough\n");
		goto end;
	}

	OPENSSL_assert(buf);
	strcpy(buf, A);
	strcat(buf, " ");
	strcat(buf, B);

	ret = outlen;
	
end:
	if (group) EC_GROUP_free(group);
	if (A) OPENSSL_free(A);
	if (B) OPENSSL_free(B);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}

