#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define R_16_1


#ifdef R_16_1

#define CRYPTO_R_n 1024
#define CRYPTO_R_k 1
#define CRYPTO_R_logq 16
#define CRYPTO_R_sigma 3
#define CRYPTO_R_t 2
#define CRYPTO_R_NTT ntt_1024_40961
#define CRYPTO_R_INTT inv_ntt_1024_40961
#define CRYPTO_R_q 40961
#define CRYPTO_R_msg 128
#define CRYPTO_RGen 3
#define CRYPTO_Rm 2
#define CRYPTO_N_INV 40921

#endif

#ifdef R_16_2

#define CRYPTO_R_n 1024
#define CRYPTO_R_k 1
#define CRYPTO_R_logq 16
#define CRYPTO_R_sigma 3
#define CRYPTO_R_t 2
#define CRYPTO_R_NTT ntt_1024_40961
#define CRYPTO_R_INTT inv_ntt_1024_40961
#define CRYPTO_R_q 40961
#define CRYPTO_R_msg 128
#define CRYPTO_RGen 5
#define CRYPTO_Rm 3
#define CRYPTO_N_INV 40921

#endif

typedef struct
{
	int *A;
	int *B;

}_CRYPTO_R_pub_struct;

typedef _CRYPTO_R_pub_struct CRYPTO_R_pub_t[1];
