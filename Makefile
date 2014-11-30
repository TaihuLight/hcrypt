
.PHONY: all test clean install

all:
	gcc -Wall -c hcrypt_ec_lib.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_ec_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_rsa_lib.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_rsa_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c bgn_lib.c        -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_bgn_lib.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_bgn_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_elgamal_lib.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_elgamal_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_paillier_lib.c -I/usr/local/include/pbc/
	gcc -Wall -c hcrypt_paillier_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_nullint_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_nullstr_mod.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_lib.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_err.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_keyring.c -I /usr/local/include/pbc/
	gcc -Wall -c hcrypt_rand.c -I /usr/local/include/pbc/
	ar rcs libhcrypt.a *.o
	gcc -Wall bgn_test.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o bgn_test -I /usr/local/include/pbc/
	gcc -Wall hcrypt_test.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt_test -I /usr/local/include/pbc/
	gcc -Wall hcrypt-keygen.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-keygen -I /usr/local/include/pbc/
	gcc -Wall hcrypt-enc.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-enc -I /usr/local/include/pbc/
	gcc -Wall hcrypt-dec.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-dec  -I /usr/local/include/pbc/
	gcc -Wall hcrypt-sum.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-sum  -I /usr/local/include/pbc/
	gcc -Wall hcrypt-sub.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-sub  -I /usr/local/include/pbc/
	gcc -Wall hcrypt-product.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o hcrypt-product  -I /usr/local/include/pbc/
	gcc -Wall keyring_test.c libhcrypt.a /usr/local/lib/libcrypto.a -lpbc -lgmp -ldl -o keyring_test  -I /usr/local/include/pbc/
	

test:
	./keyring_test

clean:
	rm -f *.o
	rm -f *.a
	rm -f *_test
	rm -f *.db
	rm -f hcrypt-keygen
	rm -f hcrypt-enc
	rm -f hcrypt-dec
	rm -f hcrypt-sum
	rm -f hcrypt-sub
	rm -f hcrypt-product
	rm -f ciphertext*

install:
	cp hcrypt.h /usr/local/include/
	cp hcrypt_keyring.h /usr/local/include/
	cp libhcrypt.a /usr/local/lib/
	cp hcrypt-keygen /usr/local/bin/
	cp hcrypt-enc /usr/local/bin/
	cp hcrypt-dec /usr/local/bin/
	cp hcrypt-sum /usr/local/bin/
	cp hcrypt-sub /usr/local/bin/
	cp hcrypt-product /usr/local/bin/

