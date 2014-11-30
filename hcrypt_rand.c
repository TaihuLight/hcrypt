#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "hcrypt.h"
#include "hcrypt_rand.h"



int hcrypt_plaintext_rand_word(hcrypt_plaintext_t *m, unsigned long max_val)
{
	int ret  = -1;
	BIGNUM *a = BN_new();
	BIGNUM *mx = BN_new();

	if (!a) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!mx) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_set_word(mx, max_val)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_rand_range(a, mx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	

	if (hcrypt_plaintext_set_word(m, BN_get_word(a)) < 0) {

		goto end;
	}

	ret = 0;
end:
	if (a) BN_free(a);
	if (mx) BN_free(mx);

	return ret;	
}


int hcrypt_rand_seed(const unsigned char *buf, size_t len)
{
	return 0;
}

int hcrypt_rand_bytes(unsigned char *buf, int len)
{
	RAND_bytes(buf, len);
	return 0;
}

int hcrypt_rand_pseudo_bytes(unsigned char *buf, int len)
{
	RAND_pseudo_bytes(buf, len);
	return 0;
}

int hcrypt_rand_gaussian_word(unsigned int *val, int min, int max)
{
	return -1;
}

#if 0
int hcrypt_rand_gaussian_polynomial(fmpz_poly_t poly, const fmpz_poly_t range)
{
	return -1;
}

int hcrypt_rand_pseudo_gaussian_polynomial(fmpz_poly_t poly, const fmpz_poly_t range)
{
	return -1;
}
#endif

