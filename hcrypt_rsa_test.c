#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/rsa.h>
#include "hcrypt_rsa.h"

int main(int argc, char **argv)
{
#if 0
	int r; 
	/* openssl rsa sample code */
	RSA *rsa = RSA_new();
	assert(rsa);

	BIGNUM *e = BN_new();
	BN_set_word(e, 65537);
	
	r = RSA_generate_key_ex(rsa, 1024, e, NULL);
	assert(r == 1);

	RSA_print_fp(stdout, rsa, 2);	

	RSA *pub_key = RSAPublicKey_dup(rsa);
	RSA *prv_key = RSAPrivateKey_dup(rsa);

	printf("\n");
	RSA_print_fp(stdout, pub_key, 2);

	printf("\n");
	RSA_print_fp(stdout, prv_key, 2);


	/* key generation and encoding */
	rsa_pubkey_t *pk = NULL;
	rsa_prvkey_t *sk = NULL;

	r = rsa_keygen(&pk, &sk);
	assert(r >= 0);
	assert(pk);
	assert(sk);

	char *pk_str = NULL;
	char *sk_str = NULL;

	pk_str = rsa_pubkey_to_str(pk);
	sk_str = rsa_prvkey_to_str(sk);
	assert(pk_str);
	assert(sk_str);
	printf("rsa public key = %s\n", pk_str);
	printf("rsa private key = %s\n", sk_str);

	/* encryption/decryption */
	rsa_plaintext_t *pt = NULL;
	rsa_ciphertext_t *ct = NULL;

	pt = rsa_plaintext_new_from_word(11223344);
	assert(pt);

	ct = rsa_ciphertext_new();
	assert(ct);

	/*
	printf("plaintext = %s\n", BN_bn2hex(pt));
	printf("e = %s\n", BN_bn2hex(pk->e));
	printf("n = %s\n", BN_bn2hex(pk->n));

	BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *bn = BN_new();
	BN_mod_exp(ct, pt, pk->e, pk->n, bn_ctx);
	return 0; 
	*/

	r = rsa_encrypt(ct, pt, pk);
	assert(r >= 0);

	char *c_str = NULL;
	c_str = rsa_ciphertext_to_new_str(ct);
	assert(c_str);
	printf("ciphertext = %s\n", c_str);		

	rsa_plaintext_free(pt);
	pt = NULL;
	pt = rsa_plaintext_new();
	assert(pt);

	r = rsa_decrypt(pt, ct, sk);
	assert(r >= 0);

	printf("plaintext = %u\n", rsa_plaintext_to_word(pt));

	/* homo-mul */
	rsa_ciphertext_t *c2 = NULL;
	c2 = rsa_ciphertext_new();
	assert(c2);

	r = rsa_plaintext_set_word(pt, 2);
	assert(r >= 0);

	r = rsa_encrypt(c2, pt, pk);
	assert(r >= 0);

	r = rsa_ciphertext_mul(c2, c2, ct, pk);
	assert(r >= 0);

	r = rsa_decrypt(pt, c2, sk);
	assert(r >= 0);
	
	printf("mul result = %u\n", rsa_plaintext_to_word(pt));
#endif	
	return 0;
}

