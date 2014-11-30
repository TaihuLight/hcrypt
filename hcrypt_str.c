#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <pbc.h>


int hcrypt_mpz_to_str(mpz_t a, char **buf, size_t *buflen)
{
	int len = gmp_snprintf(NULL, 0, "%ZX", a);
	if (!buf)
		return (len + 1);
	if (*buflen < len + 1) {
		return -1;
	}
	gmp_snprintf(*buf, *buflen, "%ZX", a);
	*buf += len;
	*buflen -= len;
	return (len + 1);
}

int hcrypt_element_to_str(element_t e, char **buf, size_t *buflen)
{

}


