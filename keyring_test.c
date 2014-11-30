#include <stdio.h>
#include "hcrypt.h"
#include "hcrypt_keyring.h"


int main(int argc, char **argv)
{
	hcrypt_keyring_t kr;

	hcrypt_keyring_init(&kr);


	hcrypt_keyring_load(&kr, stdin);
	hcrypt_keyring_save(&kr, stdout);

	return 0;
}

