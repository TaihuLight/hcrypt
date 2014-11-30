#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>
#include "hcrypt_ec.h"


int main(int argc, char **argv)
{
	int r;
	
	ec_pubkey_t *pk = NULL;
	ec_prvkey_t *sk = NULL;

	printf("  ec_keygen() ");
	r = ec_keygen(&pk, &sk);
	assert(r >= 0);
	assert(pk);
	assert(sk);
	printf("ok\n");

	char pk_str[1024];
	char sk_str[1024];	
	r = ec_pubkey_to_str(pk, pk_str, sizeof(pk_str));
	r = ec_prvkey_to_str(sk, sk_str, sizeof(sk_str));


	printf(" public key =  %s\n", pk_str);	
	printf(" private key = %s\n", sk_str);
	
	ec_pubkey_free(pk);
	ec_prvkey_free(sk);
	pk = NULL;
	sk = NULL;

	pk = ec_pubkey_new();
	sk = ec_prvkey_new();
	assert(pk);
	assert(sk);

	r = ec_pubkey_set_str(pk, pk_str);
	assert(r >= 0);
	r = ec_prvkey_set_str(sk, sk_str);
	assert(r >= 0);

	ec_plaintext_t *pt = NULL;
	ec_ciphertext_t *ct = NULL;

	pt = ec_plaintext_new();
	ct = ec_ciphertext_new();
	assert(pt);
	assert(ct);

	printf(" plaintext = %d\n", 52200);
	r = ec_plaintext_set_word(pt, 52200);
	assert(r >= 0);
	
	r = ec_encrypt(ct, pt, pk);
	assert(r >= 0);

	char ct_buf[4096];
	r = ec_ciphertext_to_str(ct, ct_buf, sizeof(ct_buf));
	assert(r >= 0);
	printf(" ciphertext = %s\n", ct_buf);


	r = ec_decrypt(pt, ct, sk);
	assert(r >= 0);	

	unsigned long a;
	r = ec_plaintext_to_word(pt, &a);
	assert(r >= 0);
	printf(" plaintext = %lu\n", a);
	
	return 0;
}
	
