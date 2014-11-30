#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <strings.h>
#include "hcrypt.h"

char *prog;

int main(int argc, char **argv)
{
	const hcrypt_algor_t *algor;
	hcrypt_plaintext_t *pt = NULL;
	hcrypt_ciphertext_t *ct = NULL;
	//hcrypt_pubkey_t *pk = NULL;
	hcrypt_prvkey_t *sk = NULL;

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
	char *skstr = strsep(&p, ",");
	skstr = strsep(&p, ",");

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

	if (!skstr) {
		fprintf(stderr, "%s: private key is null in `%s'\n", prog, argv[1]);
		return -1;
	}

	if (!(algor = hcrypt_algor_from_name(algstr))) {
		fprintf(stderr, "%s: invalid algor `%s'\n", prog, argv[1]);
		return -1;
	}

	if (hcrypt_prvkey_new_str(algor, &sk, skstr) < 0) {
		fprintf(stderr, "%s: invalid private key data\n", prog);
		return -1;
	}

	if (hcrypt_plaintext_new(algor, &pt) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;
	}

	if (hcrypt_ciphertext_new((hcrypt_pubkey_t *)sk, &ct) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;	
	}
	
	int i = 0;
	while (fgets(buf, sizeof(buf), stdin)) {

		//fprintf(stderr, "%s: %s\n", prog, buf);

		char *ptr;

		ptr = strchr(buf, '\r');
		if (ptr) *ptr = 0;
		ptr = strchr(buf, '\n');
		if (ptr) *ptr = 0;

		//printf("%s (%s %d): ciphertext = %s\n", prog, __FILE__, __LINE__, buf);
		
		i++;

		if (hcrypt_ciphertext_set_str(ct, buf) < 0) {
			fprintf(stderr, "%s: invalid ciphertext %s: %s %d\n", prog, buf, __FILE__, __LINE__);
			return -1;
		}

		//fprintf(stderr, "%s %d\n", __FILE__, __LINE__);

		//printf("we stoped here\n");


		// FIXME: decrypt not finish and failed SHOULD return different value
		if (hcrypt_decrypt(pt, ct, sk) < 0) {
			//fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
			//return -1;
			puts("1");
		} else {
		//	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		
			if (hcrypt_plaintext_to_str(pt, buf, sizeof(buf)) < 0) {
				fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
				return -1;
			}

			printf("%s\n", buf);
		}
	}
	
	return 0;
}





