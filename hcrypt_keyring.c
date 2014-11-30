#include <stdio.h>
#include <string.h>
#include "hcrypt_keyring.h"


int hcrypt_keyring_init(hcrypt_keyring_t *kr)
{
	int i;
	for (i = 0; i < HCRYPT_NUM_ALGORS; i++) {
		kr->pk[i] = NULL;	
		kr->sk[i] = NULL;
	}
	kr->count = 0;
	return 0;	
}

void hcrypt_keyring_cleanup(hcrypt_keyring_t *kr)
{
	int i;
	for (i = 0; i < HCRYPT_NUM_ALGORS; i++) {
		if (kr->pk[i]) kr->pk[i] = NULL;
		if (kr->sk[i]) kr->sk[i] = NULL;
	}
	kr->count = 0;
}

int hcrypt_keyring_generate(hcrypt_keyring_t *kr)
{
	int ret = -1;
	int i;
	char *hcrypt_algors[] = {
		"nullint",
		"nullstr",
		"ecies",
		"rsa",
		"elgamal",
		"ecelg",
		"paillier",
		"bgn",
	};

	for (i = 0; i < sizeof(hcrypt_algors)/sizeof(hcrypt_algors[0]); i++) {

		const hcrypt_algor_t *algor = hcrypt_algor_from_name(hcrypt_algors[i]);
		hcrypt_pubkey_t *pk = NULL;
		hcrypt_prvkey_t *sk = NULL;

		if (hcrypt_keygen(algor, &pk, &sk) < 0) {
			fprintf(stderr, "%s (%s %d): `%s' keygen error\n",
				__FUNCTION__, __FILE__, __LINE__, hcrypt_algors[i]);
			goto end;
		}

		kr->pk[i] = pk;
		kr->sk[i] = sk;
	}
	
	kr->count = i;

	
	ret = 0;

end:
	if (ret < 0) hcrypt_keyring_cleanup(kr);
	return ret;
}

int hcrypt_keyring_num_pubkeys(hcrypt_keyring_t *kr)
{
	return kr->count;
}

int hcrypt_keyring_num_prvkeys(hcrypt_keyring_t *kr)
{
	return kr->count;
}

int hcrypt_keyring_num_keys(hcrypt_keyring_t *kr)
{
	return kr->count;
}	

hcrypt_pubkey_t *hcrypt_keyring_get0_pubkey_by_algor(hcrypt_keyring_t *kr, const hcrypt_algor_t *algor)
{
	int i;
	for (i = 0; i < kr->count; i++) {
		if (kr->pk[i]) {
			if (hcrypt_pubkey_algor(kr->pk[i]) == algor) {
				return kr->pk[i];
			}
		}
	}
	return NULL;
}

hcrypt_prvkey_t *hcrypt_keyring_get0_prvkey_by_algor(hcrypt_keyring_t *kr, const hcrypt_algor_t *algor)
{
	int i;
	for (i = 0; i < kr->count; i++) {
		if (kr->sk[i]) {
			if (hcrypt_prvkey_algor(kr->sk[i]) == algor) {
				return kr->sk[i];
			}
		}
	}
	return NULL;
}

hcrypt_pubkey_t *hcrypt_keyring_get0_pubkey_by_name(hcrypt_keyring_t *kr, const char *name)
{
	return hcrypt_keyring_get0_pubkey_by_algor(kr, hcrypt_algor_from_name(name));
}

hcrypt_prvkey_t *hcrypt_keyring_get0_prvkey_by_name(hcrypt_keyring_t *kr, const char *name)
{
	return hcrypt_keyring_get0_prvkey_by_algor(kr, hcrypt_algor_from_name(name));
}

int hcrypt_keyring_save(hcrypt_keyring_t *kr, FILE *fp)
{
	int i;
	for (i = 0; i < kr->count; i++) {

		char buf[8000];
		const char *alg_str;
	
		if (kr->pk[i]) {
			alg_str = hcrypt_pubkey_algor_name(kr->pk[i]);

		} else if (kr->sk[i]) {
			alg_str = hcrypt_prvkey_algor_name(kr->sk[i]);

		} else {
			alg_str = NULL;
			fprintf(stderr, "%s (%s %d): invalid keyring\n",
				__FUNCTION__, __FILE__, __LINE__);
			return -1;
		}
		fprintf(fp, "%s,", alg_str);
		
		if (kr->pk[i]) {
			
			if (hcrypt_pubkey_to_str(kr->pk[i], buf, sizeof(buf)) < 0) {
				fprintf(stderr, "%s (%s %d): inner error\n",
					__FUNCTION__, __FILE__, __LINE__);
				return -1;
			}

			fputs(buf, fp);

		}
 
		fputs(",", fp);

		if (kr->sk[i]) {
			if (hcrypt_prvkey_to_str(kr->sk[i], buf, sizeof(buf)) < 0) {
				fprintf(stderr, "%s (%s %d): inner error\n",
					__FUNCTION__, __FILE__, __LINE__);
				return -1;
			}
			fputs(buf, fp);
		}
		
		fputs("\n", fp);

	}

	return 0;
}

int hcrypt_keyring_load(hcrypt_keyring_t *kr, FILE *fp)
{
	int ret = -1;
	char line[8000];
	char *alg_str;
	char *pk_str;
	char *sk_str;
	char *p;
	const hcrypt_algor_t *algor;
	hcrypt_pubkey_t *pk;
	hcrypt_prvkey_t *sk;
	
	while (fgets(line, sizeof(line), fp)) {

		p = line;
		alg_str = strsep(&p, ",");
		pk_str = strsep(&p, ",");
		sk_str = strsep(&p, ",");
		pk = NULL;
		sk = NULL;

		if (!(algor = hcrypt_algor_from_name(alg_str))) {
			fprintf(stderr, "%s (%s %d): unknown algor `%s'\n",
				__FUNCTION__, __FILE__, __LINE__, alg_str);
			goto end;
		}

		if (hcrypt_keyring_get0_pubkey_by_algor(kr, algor) ||
			hcrypt_keyring_get0_prvkey_by_algor(kr, algor)) {
			fprintf(stderr, "%s (%s %d): algor `%s' already exist\n",
				__FUNCTION__, __FILE__, __LINE__, alg_str);
			goto end;
		}

		if (!pk_str && !sk_str) {
			fprintf(stderr, "%s (%s %d): key not exist\n",
				__FUNCTION__, __FILE__, __LINE__);
			goto end;
		}

		if (pk_str) {
			if (hcrypt_pubkey_new_str(algor, &pk, pk_str) < 0) {
				fprintf(stderr, "%s (%s %d): parse pubkey `%s' failed\n",
					__FUNCTION__, __FILE__, __LINE__, pk_str);
				goto end;
			}
			kr->pk[kr->count] = pk;
		}
	
		if (sk_str) {
			if (hcrypt_prvkey_new_str(algor, &sk, sk_str) < 0) {
				fprintf(stderr, "%s (%s %d): parse prvkey `%s' failed\n",
					__FUNCTION__, __FILE__, __LINE__, sk_str);
				goto end;
			}
			kr->sk[kr->count] = sk;
	
		}
		
		kr->count++;
	}

	ret = 0;

end:
	if (ret < 0) hcrypt_keyring_cleanup(kr);
	return ret;
}

