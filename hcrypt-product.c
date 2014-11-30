#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <assert.h>
#include <strings.h>
#include "hcrypt.h"
#include "hcrypt_ec.h"

char *prog;

int main(int argc, char **argv)
{
	const hcrypt_algor_t *algor;
	hcrypt_ciphertext_t *a = NULL;
	hcrypt_ciphertext_t *ct = NULL;
	hcrypt_pubkey_t *pk = NULL;
	//hcrypt_prvkey_t *sk = NULL;

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

	{
		/*
		printf("%s %d: algor = %s\n", __FILE__, __LINE__, algstr);
		printf("%s %d: pk = %s\n", __FILE__, __LINE__, pkstr);
		printf("%s %d: sk = %s\n", __FILE__, __LINE__, skstr);
		*/
	}

	if (!algstr) {
		fprintf(stderr, "%s: algor is null in `%s'\n", prog, argv[1]);
		return -1;
	}

	if (!pkstr) {
		fprintf(stderr, "%s: private key is null in `%s'\n", prog, argv[1]);
		return -1;
	}

	if (!(algor = hcrypt_algor_from_name(algstr))) {
		fprintf(stderr, "%s: invalid algor `%s'\n", prog, argv[1]);
		return -1;
	}

	if (hcrypt_pubkey_new_str(algor, &pk, pkstr) < 0) {
		fprintf(stderr, "%s: invalid private key data\n", prog);
		return -1;
	}

	if (hcrypt_ciphertext_new(pk, &a) < 0) {
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

		char *p;

		if ((p = strchr(buf, '\r'))) *p = 0;
		if ((p = strchr(buf, '\n'))) *p = 0;


		if (i == 1) {
			if (hcrypt_ciphertext_set_str(ct, buf) < 0) {
				fprintf(stderr, "%s: invalid ciphertext %s: %s %d\n", prog, buf, __FILE__, __LINE__);
				return -1;
			}

		} else {
			if (hcrypt_ciphertext_set_str(a, buf) < 0) {
				fprintf(stderr, "%s: invalid ciphertext %s: %s %d\n", prog, buf, __FILE__, __LINE__);
				return -1;
			}

			if (hcrypt_ciphertext_mul(ct, ct, a, pk) < 0) {
				fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
				return -1;
			}

		}
	}

	if (hcrypt_ciphertext_to_str(ct, buf, sizeof(buf)) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;
	}

	printf("%s\n", buf);
	
	return 0;
}


