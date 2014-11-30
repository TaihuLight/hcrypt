#include "hcrypt.h"


const char *hcrypt_errmsg(int err_code)
{
	switch (err_code) {
	case 0:
		return "OK";
	default:
		return "Error";
	}

}

