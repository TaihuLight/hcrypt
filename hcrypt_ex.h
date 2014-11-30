
int hcrypt_ciphertext_xor(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return hcrypt_ciphertext_add(r, a, b, pk);	
}

int hcrypt_ciphertext_and(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	return hcrypt_ciphertext_mul(r, a, b, pk);
}

int hcrypt_ciphertext_add_one(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_pubkey_t *pk)
{
	return -1;
}

int hcrypt_ciphertext_not(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_pubkey_t *pk)
{
	return hcrypt_ciphertext_add_one(r, a, pk);
}

int hcrypt_ciphertext_or(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	
	hcrypt_ciphertext_mul(r, a, b, pk);
	hcrypt_ciphertext_add(r, r, a, pk);
	hcrypt_ciphertext_add(r, r, b, pk);

	return 0;
}

int hcrypt_ciphertext_bfiltertest(hcrypt_ciphertext_t *r,
	hcrypt_ciphertext_t *a, hcrypt_ciphertext_t *b, hcrypt_pubkey_t *pk)
{
	hcrypt_ciphertext_mul(r, a, b, pk);
	hcrypt_ciphertext_add(r, r, a, pk);
	hcrypt_ciphertext_add_one(r, r, pk);

	return 0;
}


