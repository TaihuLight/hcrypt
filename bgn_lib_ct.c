ciphertext_set_str(bgn_ciphertext_t *c, const char *str)
{
	unsigned char bin[4096];
	int len;

	if (str[0] == '0') {
		c->level = 0;
	} else if (str[0] == '1') {
		c->level = 1;
	} else {
		fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n", __FUNCTION__, __FILE__, __LINE__, str);
		return -1;
	}

	fprintf(stderr, "info: %s (%s %d): level = %d\n", __FUNCTION__, __FILE__, __LINE__, c->level);

	if (str[1] != ' ') {
		fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n", __FUNCTION__, __FILE__, __LINE__, str);
		return -1;
	}

	if ((len = hex2bin(str + 2, bin, sizeof(bin))) <= 0) {
		fprintf(stderr, "%s (%s %d): invalid data `%s'\n", __FUNCTION__, __FILE__, __LINE__, str);
		return -1;
	}

	if (c->level == 0) {
		element_from_bytes_compressed(c->c, bin);
			
	} else if (c->level == 1) {
		element_from_bytes(c->c, bin);
	}

	return 0;
}

int bgn_ciphertext_to_str(bgn_ciphertext_t *c, char *buf, size_t buflen)
{
	int outlen;
	int nbytes;
	unsigned char bytes[4096];

	if (c->level == 0)
		nbytes = element_length_in_bytes_compressed(c->c);
	else	nbytes = element_length_in_bytes(c->c);

	outlen = nbytes * 2 + 3;

	if (!buf) {
		return outlen;
	}
	
	if (buflen < outlen) {
		fprintf(stderr, "%s: buffer too small\n", __FUNCTION__);
		return -1;
	}

	buf[0] = c->level == 0 ? '0' : '1';
	buf[1] = ' ';

	if (c->level == 0)
		element_to_bytes_compressed(bytes, c->c);
	else	element_to_bytes(bytes, c->c);	
      
	bin2hex(bytes, nbytes, buf + 2, buflen); 
	buf[outlen - 1] = 0;

	return outlen;
}

void bgn_ciphertext_cleanup(bgn_ciphertext_t *c)
{
	c->level = 0;
	element_clear(c->c);
}

