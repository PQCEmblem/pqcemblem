#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define R_14_1

#ifdef R_14_1

#define CRYPTO_R_n 1024
#define CRYPTO_R_k 1
#define CRYPTO_R_logq 14
#define CRYPTO_R_sigma 3
#define CRYPTO_R_t 1
#define CRYPTO_R_NTT ntt_1024_12289
#define CRYPTO_R_INTT inv_ntt_1024_12289
#define CRYPTO_R_q 12289
#define CRYPTO_R_msg 256
#define CRYPTO_RGen 3
#define CRYPTO_Rm 2
#define CRYPTO_N_INV 12277

#endif

#ifdef R_14_2

#define CRYPTO_R_n 1024
#define CRYPTO_R_k 1
#define CRYPTO_R_logq 14
#define CRYPTO_R_sigma 3
#define CRYPTO_R_t 1
#define CRYPTO_R_NTT ntt_1024_12289
#define CRYPTO_R_INTT inv_ntt_1024_12289
#define CRYPTO_R_q 12289
#define CRYPTO_R_msg 256
#define CRYPTO_RGen 5
#define CRYPTO_Rm 3
#define CRYPTO_N_INV 12277

#endif

typedef struct
{
	int *A;
	int *B;

}_CRYPTO_R_pub_struct;

typedef _CRYPTO_R_pub_struct CRYPTO_R_pub_t[1];
