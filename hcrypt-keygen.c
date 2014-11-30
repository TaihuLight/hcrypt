#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include "hcrypt.h"

int main(int argc, char **argv)
{
	char *prog = basename(argv[0]);
	const hcrypt_algor_t *algor;
	hcrypt_pubkey_t *pk = NULL;
	hcrypt_prvkey_t *sk = NULL;
	char buf[4096];
	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: %s [%s|%s|%s|%s|%s|%s|%s]\n", prog,
			hcrypt_algor_name(hcrypt_nullint()),
			hcrypt_algor_name(hcrypt_nullstr()),
			hcrypt_algor_name(hcrypt_rsa()),
			hcrypt_algor_name(hcrypt_elgamal()),
			hcrypt_algor_name(hcrypt_ec()),
			hcrypt_algor_name(hcrypt_paillier()),
			hcrypt_algor_name(hcrypt_bgn())
			);
		return -1;
	}

	for (i = 1; i < argc; i++) {
		
		if (!(algor = hcrypt_algor_from_name(argv[i]))) {
			fprintf(stderr, "%s: invalid algor `%s'\n", prog, argv[i]);
			return -1;
		}
		printf("%s,", hcrypt_algor_name(algor));

		if (hcrypt_keygen(algor, &pk, &sk) < 0) {
			fprintf(stderr, "%s: inner error\n", prog);
			return -1;
		}

		if (hcrypt_pubkey_to_str(pk, buf, sizeof(buf)) < 0) {
			return -1;
		}
		printf("%s,", buf);

		if (hcrypt_prvkey_to_str(sk, buf, sizeof(buf)) < 0) {
			return -1;
		}
		printf("%s\n", buf);

		hcrypt_pubkey_free(pk);
		hcrypt_prvkey_free(sk);
		pk = NULL;
		sk = NULL;
	}

	return 0;
}
