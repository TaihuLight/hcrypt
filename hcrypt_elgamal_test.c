#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "hcrypt_elgamal.h"

int main(int argc, char **argv)
{
	int r;

	elgamal_pubkey_t *pk = NULL;
	elgamal_prvkey_t *sk = NULL;

	r = elgamal_keygen(&pk, &sk);
	assert(r == 0 && pk && sk);
	printf("elgamal_keygen() ok\n");

	elgamal_plaintext_t *p1 = elgamal_plaintext_new();
	elgamal_ciphertext_t *c1 = elgamal_ciphertext_new();
	assert(p1 && c1);

	r = elgamal_plaintext_set_word(p1, 11223344);
	assert(r == 0);

	r = elgamal_encrypt(c1, p1, pk);
	assert(r == 0);

	char buffer[40960];
	r = elgamal_ciphertext_to_str(c1, buffer, sizeof(buffer));
	assert(r >= 0);

	printf("ciphertext (%zu-bytes, %zu-chars): %s\n", strlen(buffer)/2, strlen(buffer), buffer);

	r = elgamal_plaintext_set_word(p1, 0);
	elgamal_decrypt(p1, c1, sk);

	unsigned long n;
	elgamal_plaintext_to_word(p1, &n);
	printf("%lu\n", n);


	elgamal_ciphertext_t *c2 = elgamal_ciphertext_new();
	elgamal_plaintext_set_word(p1, 2);
	elgamal_encrypt(c2, p1, pk);
	elgamal_ciphertext_mul(c2, c2, c1, pk);
	elgamal_decrypt(p1, c2, sk);
	elgamal_plaintext_to_word(p1, &n);
	printf("%lu\n", n);


	return 0;
}


