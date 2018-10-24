#pragma once


#define CRYPTO_SECRETKEYBYTES 4096
#define CRYPTO_PUBLICKEYBYTES 8912
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 8256


#define CRYPTO_ALGNAME "R_EMBLEM" 

int crypto_kem_keypair(unsigned char *, unsigned char *);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
