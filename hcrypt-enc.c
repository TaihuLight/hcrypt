#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include "hcrypt.h"

char *prog;

/*
int hcrypt_encrypt_fp(FILE *out_fp, FILE *in_fp, hcrypt_pubkey_t *pk)
{
	char buf[4096];
	hcrypt_plaintext_t *m = NULL;
	hcrypt_ciphertext_t *c = NULL;


	if (hcrypt_plaintext_new(&m) < 0) {
		return -1;
	}

	if (hcrypt_ciphertext_new(pk, &c) < 0) {
		return -1;
	}

	while (fgets(buf, sizeof(buf), in_fp)) {
		return -1;
	}

	return 0;
}
*/

int main(int argc, char **argv)
{
	const hcrypt_algor_t *algor;
	hcrypt_plaintext_t *pt = NULL;
	hcrypt_ciphertext_t *ct = NULL;
	hcrypt_pubkey_t *pk = NULL;

	prog = basename(argv[0]);
	
	if (argc < 2) {
		fprintf(stderr, "usage: %s <key-file>\n", prog);
		fprintf(stderr, "  read integer values from stdin\n");
		fprintf(stderr, "  write corresponding ciphertext to stdout\n");
		return -1;
	}

	hcrypt_library_init();


	FILE *fp = NULL;
	if (!(fp = fopen(argv[1], "r"))) {
		fprintf(stderr, "%s: open key file `%s' failed\n", prog, argv[1]);
		return -1;
	}

	char buf[4096*4];
	if (!fgets(buf, sizeof(buf), fp)) {
		return -1;
	}

	char *p = buf;
	char *algstr = strsep(&p, ",");
	char *pkstr = strsep(&p, ",");

	if (!algstr) {
		fprintf(stderr, "%s: algor is null in `%s'\n", prog, argv[1]);
		return -1;
	}

	if (!pkstr) {
		fprintf(stderr, "%s: public key is null in `%s'\n", prog, argv[1]);
		return -1;
	}

	//printf("algor = %s\n", algstr);
	//printf("pkstr = %s\n", pkstr);
	
	if (!(algor = hcrypt_algor_from_name(algstr))) {
		fprintf(stderr, "%s: invalid algor `%s'\n", prog, argv[1]);
		return -1;
	}
	
	//printf("SDKLFJLSDKFJLSJDF\n");
	if (hcrypt_pubkey_new_str(algor, &pk, pkstr) < 0) {
		fprintf(stderr, "%s: invalid public key data\n", prog);
		return -1;
	}

	if (hcrypt_plaintext_new(algor, &pt) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;
	}

	if (hcrypt_ciphertext_new(pk, &ct) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;	
	}
	
	int i = 0;
	while (fgets(buf, sizeof(buf), stdin)) {

		i++;

		//printf("%s\n", buf);

		/*
		long n;
		if ((n = strtol(buf, NULL, 10)) < 0) {
			fprintf(stderr, "%s: input should not be negative at line %d\n", prog, i);
			return -1;
		}
		
		if (hcrypt_plaintext_set_word(pt, n) < 0) {
			fprintf(stderr, "%s: %s(%ld) : %s %d\n", prog, __FUNCTION__, n, __FILE__, __LINE__);
			return -1;
		}
		*/

		if (hcrypt_plaintext_set_str(pt, buf) < 0) {
			fprintf(stderr, "%s: invalid input %s: %s %d\n", prog, buf, __FILE__, __LINE__);
			return -1; 
		}

	
		if (hcrypt_encrypt(ct, pt, pk) < 0) {
			fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
			return -1;
		}
		
		if (hcrypt_ciphertext_to_str(ct, buf, sizeof(buf)) < 0) {
			fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
			return -1;
		}

		printf("%s\n", buf);
		
	}
	
	return 0;
}

