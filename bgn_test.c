#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>
#include "bgn.h"

char *prog;

int main(int argc, char **argv)
{
	int ret;
	char buf[40960];
	bgn_key_t sk, pk;
	unsigned long a = 25;

	bgn_ciphertext_t c2;


	prog = basename(argv[0]);

	printf("%s: test bgn_key_generate() : ", prog);
	ret = bgn_key_generate(&sk, 1024);
	assert(ret >= 0);
	printf("ok\n");


	printf("%s: test bgn_key_to_str() encode private key : ", prog);
	ret = bgn_key_to_str(&sk, buf, sizeof(buf), 1);
	assert(ret >= 0);
	printf("ok\n");
	printf("%s: private key: %s\n", prog, buf);


	printf("%s: test bgn_key_init_set() : ", prog);
	ret = bgn_key_init_set(&pk, &sk, 0);
	assert(ret >= 0);
	printf("ok\n");


	
	printf("%s: test bgn_key_to_str() encode public key : ", prog);
	ret = bgn_key_to_str(&pk, buf, sizeof(buf), 0);
	assert(ret >= 0);
	printf("ok\n");
	printf("%s: public key: %s\n", prog, buf);


	bgn_plaintext_t m;
	printf("%s: test bgn_plaintext_init_set_word(%lu) : ", prog, a);
	ret = bgn_plaintext_init_set_word(&m, a);
	assert(ret >= 0);
	printf("ok\n");

	bgn_ciphertext_t c;
	printf("%s: test bgn_encrypt(%lu) : ", prog, a);
	ret = bgn_encrypt(&c, &m, &pk);
	assert(ret >= 0);
	printf("ok\n");

	printf("%s: test bgn_ciphertext_to_str() : ", prog);
	ret = bgn_ciphertext_to_str(&c, buf, sizeof(buf));
	assert(ret >= 0);
	printf("ok\n");
	printf("%s: ciphertext: %s\n", prog, buf);


	ret = bgn_ciphertext_init_set_str(&c, buf, &pk);
	assert(ret >= 0);
	
	bgn_plaintext_t r;
	printf("%s: test bgn_decrypt() : ", prog);
	ret = bgn_decrypt(&r, &c, &sk);
	assert(ret >= 0);
	printf("ok\n");

	unsigned long ra = 0;
	ret = bgn_plaintext_to_word(&r, &ra);
	assert(ret >= 0);
	printf("%s: decrypted plaintext: %lu\n", prog, ra);


	printf("%s: test bgn_ciphertext_add() : ", prog);
	ret = bgn_ciphertext_add(&c2, &c, &c, &pk);
	assert(ret >= 0);
	printf("ok\n");


	ret = bgn_decrypt(&r, &c2, &sk);
	assert(ret >= 0);
	
	ret = bgn_plaintext_to_word(&r, &a);
	assert(ret >= 0);

	printf("%s: add result: %lu\n", prog, a);


	// c2 = 5 + 5 = 10
	bgn_ciphertext_to_str(&c2, buf, sizeof(buf));
	printf("ciphertext = %s\n", buf);

	bgn_ciphertext_t c3;
	bgn_ciphertext_mul(&c3, &c, &c2, &sk);
	// c3 = 5 * 10 = 50
	printf("compute c3 ok\n");
	bgn_ciphertext_to_str(&c3, buf, sizeof(buf));
	printf("ciphertext = %s\n", buf);
	
	bgn_decrypt(&r, &c3, &sk);
	
	bgn_plaintext_to_word(&r, &a);
	printf("plaintext = %lu\n", a);


	bgn_key_cleanup(&sk);
	bgn_key_cleanup(&pk);
	return 0;
}

