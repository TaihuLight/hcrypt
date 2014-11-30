#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <assert.h>
#include <strings.h>
#include "hcrypt.h"
#include "hcrypt_keyring.h"

char *prog;

int main(int argc, char **argv)
{
	int ret = -1;
	FILE *krfp = NULL;
	FILE *infp = NULL;
	char buf[8000];
	char *p;
	hcrypt_keyring_t kr;
	hcrypt_pubkey_t *pk;
	hcrypt_ciphertext_t *r = NULL;
	hcrypt_ciphertext_t *a = NULL;
	hcrypt_ciphertext_t *b = NULL;

	prog = basename(argv[0]);
	
	if (argc < 3) {
		fprintf(stderr, "usage: %s <key-file> <cfile1>\n", prog);
		fprintf(stderr, "  write corresponding ciphertext to stdout\n");
		return -1;
	}

	hcrypt_library_init();
	hcrypt_keyring_init(&kr);

	if (!(krfp = fopen(argv[1], "r"))) {
		fprintf(stderr, "%s: open key file `%s' failed\n", prog, argv[1]);
		return -1;
	}
	if (hcrypt_keyring_load(&kr, krfp) < 0) {
		fprintf(stderr, "%s (%s %d): load keyring failed\n",
			prog, __FILE__, __LINE__);
		goto end;
	}
	if (!(pk = kr.pk[0])) {
		fprintf(stderr, "%s (%s %d): no public key\n",
			prog, __FILE__, __LINE__);
		goto end;
	}

	if (hcrypt_ciphertext_new(pk, &r) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;	
	}
	if (hcrypt_ciphertext_new(pk, &a) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;	
	}
	if (hcrypt_ciphertext_new(pk, &b) < 0) {
		fprintf(stderr, "%s: %s %d\n", prog, __FILE__, __LINE__);
		return -1;	
	}


	if (!(infp = fopen(argv[2], "r"))) {
		fprintf(stderr, "%s (%s %d): open ciphertext file `%s' failed\n",
			prog, __FILE__, __LINE__, argv[2]);
		goto end;
	}

	while (fgets(buf, sizeof(buf), infp)) {

		if ((p = strchr(buf, '\r'))) *p = 0;
		if ((p = strchr(buf, '\n'))) *p = 0;
		if (hcrypt_ciphertext_set_str(a, buf) < 0) {
			fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n",
				prog, __FILE__, __LINE__, buf);
			goto end;
		}


		if (!fgets(buf, sizeof(buf), stdin)) {
			fprintf(stderr, "%s: not enough ciphertext in stdin\n", prog);
			goto end;
		}

		if ((p = strchr(buf, '\r'))) *p = 0;
		if ((p = strchr(buf, '\n'))) *p = 0;
		if (hcrypt_ciphertext_set_str(b, buf) < 0) {
			fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n",
				prog, __FILE__, __LINE__, buf);
			goto end;
		}

		if (hcrypt_ciphertext_sub(r, a, b, pk) < 0) {
			fprintf(stderr, "%s (%s %d): inner error\n",
				prog, __FILE__, __LINE__);
			goto end;
		}

		if (hcrypt_ciphertext_to_str(r, buf, sizeof(buf)) < 0) {
			fprintf(stderr, "%s (%s %d): inner error\n",
				prog, __FILE__, __LINE__);
			goto end;
		}
		puts(buf);
	}

	ret = 0;

end:
	hcrypt_keyring_cleanup(&kr);
	if (r) hcrypt_ciphertext_free(r);
	if (a) hcrypt_ciphertext_free(a);
	if (b) hcrypt_ciphertext_free(b);
	
	return ret;
}




