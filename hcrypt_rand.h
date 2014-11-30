#ifndef HCRYPT_RAND_H
#define HCRYPT_RAND_H

//#include <flint/flint.h>

#ifdef __cplusplus
extern "C" {
#endif


int hcrypt_rand_seed(const unsigned char *buf, size_t len);
int hcrypt_rand_bytes(unsigned char *buf, int len);
int hcrypt_rand_pseudo_bytes(unsigned char *buf, int len);
int hcrypt_rand_gaussian_word(unsigned int *val, int min, int max);
#if 0
int hcrypt_rand_gaussian_polynomial(fmpz_poly_t poly, const fmpz_poly_t range);
int hcrypt_rand_pseudo_gaussian_polynomial(fmpz_poly_t poly, const fmpz_poly_t range);
#endif

#ifdef __cplusplus
}
#endif
#endif
