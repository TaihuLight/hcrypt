#!/bin/bash

./hcrypt-keygen paillier > keyring.csv

echo 1 | ./hcrypt-enc keyring.csv > ciphertext.txt
cat ciphertext.txt | ./hcrypt-dec keyring.csv
echo 2 | ./hcrypt-enc keyring.csv > ciphertext.txt
cat ciphertext.txt | ./hcrypt-dec keyring.csv
echo 1000 | ./hcrypt-enc keyring.csv > ciphertext.txt
cat ciphertext.txt | ./hcrypt-dec keyring.csv
echo 60000 | ./hcrypt-enc keyring.csv > ciphertext.txt
cat ciphertext.txt | ./hcrypt-dec keyring.csv


echo 1 | ./hcrypt-enc keyring.csv > ciphertext.txt
echo 2 | ./hcrypt-enc keyring.csv >> ciphertext.txt
echo 3 | ./hcrypt-enc keyring.csv >> ciphertext.txt
echo 4 | ./hcrypt-enc keyring.csv >> ciphertext.txt
echo 5 | ./hcrypt-enc keyring.csv >> ciphertext.txt
cat ciphertext.txt | ./hcrypt-sum keyring.csv > ciphertext.sum
cat ciphertext.sum | ./hcrypt-dec keyring.csv


