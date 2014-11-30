#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "hcrypt.h"

/*
 * hcrypt <algor> command 
 * hcrypt encrypt <seckey> 
 * hcrypt decrypt <pubkey>
 * hcrypt add     <pubkey>
 * hcrypt mul     <pubkey>


 * hcrypt genkey rsa guanzhi
 * hcrypt genkey algor=rsa label=guanzhi
 *
 */


static int _encrypt(hcrypt_pubkey_t *pk)
{
	printf("this should output ciphertext\n");
	return 0;		
}

static int _decrypt(hcrypt_prvkey_t *sk)
{
	printf("this should output plaintext\n");
	return 0;
}

static int _addciphertext(hcrypt_context_t *ctx, hcrypt_pubkey_t *pk)
{
	hcrypt_ciphertext_t *r;
	hcrypt_ciphertext_t *c;
	char buffer[2048];

	hcrypt_ciphertext_new(ctx, &r);
	hcrypt_ciphertext_new(ctx, &c);

	while (fread(buffer, 1, sizeof(buffer), stdin)) {
		hcrypt_ciphertext_set_str(ctx, c, buffer);
		hcrypt_add(ctx, r, r, c, pk);
	}

	return 0;
}

static int _mulciphertext(hcrypt_pubkey_t *pk)
{
	hcrypt_ciphertext_t *c;
	hcrypt_ciphertext_t *r;
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	char *prog = basename(argv[0]);
	char *cmd;
	int verbose = 0;

	hcrypt_context_t *ctx;
	hcrypt_pubkey_t *pk;
	hcrypt_prvkey_t *sk;
	hcrypt_plaintext_t *p1;
	hcrypt_plaintext_t *p2;
	hcrypt_ciphertext_t *c1;
	hcrypt_ciphertext_t *c2;
	hcrypt_ciphertext_t *r, *a, *b;

	if (argc < 2) {
		fprintf(stderr, "%s version 0.1 (%s %s)\n", prog, __DATE__, __TIME__);
usage:
		fprintf(stderr, "usage:\n", prog);
		fprintf(stderr, "  %s genkey <bits>\n", prog);
		fprintf(stderr, "  %s encrypt <pubkey>\n", prog);
		fprintf(stderr, "  %s decrypt <prvkey>\n", prog);
		fprintf(stderr, "  %s add <pubkey>\n", prog);
		fprintf(stderr, "  %s mul <pubkey>\n", prog);
		return -1;
	}

	if (hcrypt_library_init(verbose, "hcrypt: ") < 0) {
		fprintf(stderr, "%s: hcrypt_library_init() failed\n", prog);
		return -1;
	}
	cmd = argv[1];
	hcrypt_context_new(&ctx, hcrypt_null(), NULL);


	if (!strcmp(cmd, "genkey")) {
		if (argc != 2) {
			fprintf(stderr, "usage: %s genkey <bits>\n", prog);
			goto end;
		}
		/*
		if (hcrypt_keygen()) {
		}
		*/
	} else if (!strcmp(cmd, "encrypt")) {
		if (argc != 2) {
		}
		if ((ret = hcrypt_pubkey_new_str(ctx, &pk, argv[2])) < 0) {
		}
		/*	
		if ((ret = hcrypt_encrypt(ctx, r, a, pk)) < 0) {
		}
		*/

	} else if (!strcmp(cmd, "decrypt")) {
				

	} else if (!strcmp(cmd, "add")) {
		// read the first line
		// parse as the result
		// loop
		//	parse and add to result 
	} else if (!strcmp(cmd, "mul")) {
	}


end:
	if (ctx) hcrypt_context_free(ctx);
	if (pk) hcrypt_pubkey_free(pk);
	if (sk) hcrypt_prvkey_free(sk);
	if (c1) hcrypt_ciphertext_free(c1);
	if (c2) hcrypt_ciphertext_free(c2);
	return ret;
}

