# hcrypt

The hcrypt is an homomorphic encryption library. The project includes the
libhcrypt library, the `hcrypt' command line tool and the `hcrypt_test' testing
code.

The libhcrypt aims to provide multiple homomorhpic encryption schemes with a
generailized interface. It hopes to implement encryption schemes including:

 rsa		- unpadded rsa, ciphertext mul
 elgamal	- elgamal encryption, ciphertext mul
 ec		- elliptic curve elgamal, ciphertext add
 paillier	- paillier cryptosystem, ciphertext add
 bgn		- boneh-Goh-Nissim, many ciphertext add, one mul
 nullint	- null algor do no encrypt/decrypt, thus support any add and mul
 nullstr

