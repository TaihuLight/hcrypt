#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "hcrypt.h"
#include "hcrypt_locl.h"


#if 0
static int test_storage(void)
{
	int r;
	int i;

	const hcrypt_algor_t *alg[3];
	hcrypt_pubkey_t *pk[3];
	hcrypt_prvkey_t *sk[3];
	char *column[3];

	alg[0] = hcrypt_nullstr();
	alg[1] = hcrypt_rsa();
	alg[2] = hcrypt_elgamal();

	column[0] = "column1";
	column[1] = "column2";
	column[2] = "column3";

	for (i = 0; i < 3; i++) {
		pk[i] = NULL;
		sk[i] = NULL;
	
		r = hcrypt_keygen(alg[i], &pk[i], &sk[i]);
		assert(r >= 0);	
	}

	assert(r >= 0);

	

	return 0;
}
#endif

static int test(const hcrypt_algor_t *algor)
{
	int r;
	hcrypt_pubkey_t *pk = NULL;
	hcrypt_prvkey_t *sk = NULL;
	hcrypt_plaintext_t *m = NULL;
	hcrypt_ciphertext_t *c = NULL;
	unsigned long a;
	char buf[4096];

	hcrypt_library_init();

	printf("test %s\n", hcrypt_algor_name(algor));

	/* keygen */
	r = hcrypt_keygen(algor, &pk, &sk);
	assert(r >= 0);
	assert(pk);
	assert(sk);

	/* pubkey encode and decode */
	memset(buf, 0, sizeof(buf));
	r = hcrypt_pubkey_to_str(pk, buf, sizeof(buf));
	assert(r >= 0);
	printf(" pk = %s\n", buf);

	r = hcrypt_pubkey_free(pk);
	assert(r >= 0);
	pk = NULL;
	
	r = hcrypt_pubkey_new_str(algor, &pk, buf);
	assert(r >= 0);
	assert(pk);

	memset(buf, 0, sizeof(buf));
	r = hcrypt_pubkey_to_str(pk, buf, sizeof(buf));
	assert(r >= 0);
	printf(" pk = %s\n", buf);

	/* prvkey encode and decode */
	memset(buf, 0, sizeof(buf));
	r = hcrypt_prvkey_to_str(sk, buf, sizeof(buf));
	assert(r >= 0);
	printf(" sk = %s\n", buf);

	r = hcrypt_prvkey_free(sk);
	assert(r >= 0);
	sk = NULL;

	r = hcrypt_prvkey_new_str(algor, &sk, buf);
	assert(r >= 0);
	assert(sk);

	memset(buf, 0, sizeof(buf));
	r = hcrypt_prvkey_to_str(sk, buf, sizeof(buf));
	assert(r >= 0);
	printf(" sk = %s\n", buf);

	/* encrypt */
	r = hcrypt_plaintext_new(algor, &m);	
	assert(r >= 0);
	assert(m);

	a = 123;
	printf(" plaintext = %lu\n", a);

	if (algor->plaintext_set_word) {
	
		r = hcrypt_plaintext_set_word(m, a);
		assert(r >= 0);
	
	} else if (algor->plaintext_set_str) {
	
		r = hcrypt_plaintext_set_str(m, "hello");
		assert(r >= 0);

	} else {
		assert(0);
	}

	r = hcrypt_ciphertext_new(pk, &c);
	assert(r >= 0);
	assert(c);

	r = hcrypt_encrypt(c, m, pk);
	assert(r >= 0);

	r = hcrypt_plaintext_free(m);
	assert(r >= 0);
	m = NULL;

	r = hcrypt_plaintext_new(algor, &m);
	assert(r >= 0);
	assert(m);

	r = hcrypt_decrypt(m, c, sk);
	assert(r >= 0);
	
	if (algor->plaintext_to_word) {

		a = 0;
		r = hcrypt_plaintext_to_word(m, &a);
		assert(r >= 0);
 
		printf(" plaintext = %lu\n", a);

	} else if (algor->plaintext_to_str) {

		char ptbuf[1024];
		r = hcrypt_plaintext_to_str(m, ptbuf, sizeof(ptbuf));
		assert(r >= 0);
	
		printf(" plaintext = %s\n", ptbuf);
	
	} else {
		assert(0);
	}	
	


	/* ciphertext encode and decode */
	memset(buf, 0, sizeof(buf));
	r = hcrypt_ciphertext_to_str(c, buf, sizeof(buf));
	assert(r >= 0);

	printf(" ciphertext = %s\n", buf);

	r = hcrypt_ciphertext_free(c);
	assert(r >= 0);
	c = NULL;

	r = hcrypt_ciphertext_new(pk, &c);
	assert(r >= 0);
	assert(c);

	r = hcrypt_ciphertext_set_str(c, buf);
	assert(r >= 0);

	memset(buf, 0, sizeof(buf));
	r = hcrypt_ciphertext_to_str(c, buf, sizeof(buf));
	assert(r >= 0);
	
	printf(" ciphertext = %s\n", buf);

	hcrypt_ciphertext_t *c2 = NULL;
	r = hcrypt_ciphertext_new(pk, &c2);
	assert(r >= 0);
	assert(c2);

	if (algor->plaintext_set_word) {

		r = hcrypt_plaintext_set_word(m, 3);
		assert(r >= 0);

	} else if (algor->plaintext_set_str) {

		r = hcrypt_plaintext_set_str(m, "world");
		assert(r >= 0);

	}

	r = hcrypt_encrypt(c2, m, pk);
	assert(r >= 0);

	/* homomorphic add */
	if (algor->add) {
	
		printf("add\n");
		
		r = hcrypt_ciphertext_add(c, c, c2, pk);
		assert(r >= 0);


		r = hcrypt_decrypt(m, c, sk);
		assert(r >= 0);

		if (algor->plaintext_to_word) {
	
			r = hcrypt_plaintext_to_word(m, &a);
			assert(r >= 0);
		
			printf(" + 3 = %lu\n", a);
		
		} else if (algor->plaintext_to_str) {
			
			char buf[1024];
			r = hcrypt_plaintext_to_str(m, buf, sizeof(buf));

			assert(r >= 0);
			printf(" + 3 = %s\n", buf);
			
		} else {
			assert(0);
		}
	}


	if (algor->mul) {

		r = hcrypt_ciphertext_mul(c, c, c2, pk);
		assert(r >= 0);

		r = hcrypt_decrypt(m, c, sk);
		assert(r >= 0);

		r = hcrypt_plaintext_to_word(m, &a);
		assert(r >= 0);

		printf(" * 3 = %lu\n", a);
		
	}

	return 0;
}

static int rsa_test(void)
{
#if 0
	int r;
	const hcrypt_algor_t *algor = hcrypt_rsa();
	hcrypt_context_t *ctx = NULL;
	hcrypt_pubkey_t *pk = NULL;
	hcrypt_prvkey_t *sk = NULL;
	//hcrypt_plaintext_t *m = NULL;
	//hcrypt_ciphertext_t *c = NULL;

	r = hcrypt_context_new(&ctx, algor, NULL);
	assert(r >= 0);
	assert(ctx);

	r = hcrypt_keygen(ctx, &pk, &sk);
	assert(r >= 0);
	assert(pk);
	assert(sk);
#endif
	return 0;
}


int main(int argc, char **argv)
{
#if 0
	const hcrypt_algor_t *algor = hcrypt_null();
	hcrypt_context_t *ctx = NULL;
	hcrypt_pubkey_t *pk = NULL;
	hcrypt_prvkey_t *sk = NULL;
	//hcrypt_plaintext_t *pt = NULL;
	//hcrypt_ciphertext_t *ct = NULL;
	char buf[1024];

	hcrypt_library_init();
	
	printf("hcrypt module: %s\n", hcrypt_algor_name(algor));

	if (hcrypt_context_new(&ctx, hcrypt_null(), NULL) < 0) {
		return -1;
	}
	if (hcrypt_keygen(ctx, &pk, &sk) < 0) {
		return -1;
	}
	
	hcrypt_pubkey_to_str(ctx, pk, buf, sizeof(buf));
	printf("public-key: %s\n", buf);

	hcrypt_prvkey_to_str(ctx, sk, buf, sizeof(buf));
	printf("private-key: %s\n", buf);

	/*
	if (hcrypt_plaintext_new_word(ctx, &pt, 123) < 0) {
		return -1;
	}
	if (hcrypt_ciphertext_new(ctx, &ct) < 0) {
		return -1;
	}
	*/

	/* rsa */

	rsa_test();	
#endif	
	test(hcrypt_elgamal());
	test(hcrypt_rsa());
	test(hcrypt_nullstr());

	rsa_test();
	//test_storage();
	
	hcrypt_library_exit();		
	return 0;
}

