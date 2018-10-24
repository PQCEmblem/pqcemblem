#include "api.h"
#include "rng.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <immintrin.h>
#include "blake2_locl.h"
#include "blake2_impl.h"
#include <x86intrin.h>


#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 1
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 32
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
#define CRYPTO_delta 32

#define _dropBits(dx, x)\
{\
int _tmp=0;\
_tmp = x >> (CRYPTO_logq-CRYPTO_t);\
_tmp = _tmp & 0xff;\
dx = _tmp;\
}

#define _MatADD(r, x, y, row_x, column_x)\
{\
int _i;\
for(_i=0; _i<row_x*column_x;_i++)\
{\
r[_i]=(x[_i]+y[_i])&CRYPTO_MASK;\
}\
}


void _BINT_to_OS(unsigned char *a, unsigned int *in, int os_len)
{

	int i;

	for (i = 0; i < os_len; i++)
	{
		a[i] = (in[i >> 2] >> (24 - 8 * (i % 4))) & 0xff;
	}


}

void _OS_to_BINT(unsigned int *a, unsigned char *os, int bint_len)
{
	int i;


	for (i = 0; i < (bint_len); i++)
	{
		a[i] = ((unsigned int)os[(i << 2)] & 0xff) << 24;
		a[i] ^= ((unsigned int)os[(i << 2) + 1] & 0xff) << 16;
		a[i] ^= ((unsigned int)os[(i << 2) + 2] & 0xff) << 8;
		a[i] ^= ((unsigned int)os[(i << 2) + 3] & 0xff);

	}

}

void SHA256_INT (unsigned int *Msg, unsigned int MLen, unsigned int *Digest)
{
	unsigned char *M_tmp;
	unsigned char D_tmp[32];

	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	SHA256(M_tmp, MLen, D_tmp);

	_OS_to_BINT (Digest, D_tmp, 8);

}

void SHA256_OS (unsigned int *Msg, unsigned int MLen, unsigned char *Digest)
{
	unsigned char *M_tmp;

	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	SHA256(M_tmp, MLen, Digest);


}

void BLAKE_INT (unsigned int *Msg, unsigned int MLen, unsigned int *Digest)
{
	unsigned char *M_tmp;
	unsigned char D_tmp[64];

	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	BLAKE2b(D_tmp, M_tmp, MLen);

	_OS_to_BINT (Digest, D_tmp, 16);


}

void BLAKE_CHAR (unsigned int *Msg, unsigned int MLen, unsigned char *Digest)
{
	unsigned char *M_tmp;


	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	BLAKE2b(Digest, M_tmp, MLen);


}


/* Generates seed and random number in {-1, 0, 1} from delta */
unsigned int _KEM_GenTrinary(int *r, unsigned int *delta, int CNT)
{
	unsigned int d_tmp[9];
	unsigned int tmp[16];
	int cnt = 0, iter=0;
	int j;

	memcpy(d_tmp, delta, 8 * sizeof(int));
	memset(tmp, 0, 16 * sizeof(int));

	while (cnt < CNT)
	{
		BLAKE_INT(d_tmp, CRYPTO_msg, tmp);
		for (j = 0; j < 16; j++)
		{
			while ((tmp[j] != 0) && (cnt<CNT))
			{

				r[cnt] = (((tmp[j] % CRYPTO_RGen) + 1) - CRYPTO_RM);
				tmp[j] = tmp[j] / CRYPTO_RGen;
				cnt++;
			}

		}

		d_tmp[0]++;
		memset(tmp, 0, 8 * sizeof(int));

	}

	// Generate Seed
	memcpy(d_tmp, delta, 8 * sizeof(int));
	SHA256_INT(d_tmp, 32, tmp);

	return tmp[0];

}

int random_modq()
{
	unsigned char r[3];
	int tmp;
	int check;

	randombytes(r,3);
	tmp = (r[0] & 0xff) | ((r[1] & 0xff) << 8)| ((r[1] & 0xff) << 16);

	return check;
}


char CDT_TABLE[512] = { 
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5,
5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11,
11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15,
16, 16, 16, 17, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20};

/* Gaussain sampling from CDT table */
int Sample_CDT_NOSEED()
{
	int sign, sample;

	sign = rand() & 1;
	sample = CDT_TABLE[(rand()&0x1ff)];

	sample = ((-sign) ^ sample) + sign;
	return sample;

}

void Sample_CDT_hash(int *x, int seed, int i)
{
	unsigned char tmp[64]={0,};
	int r[8]={0,}, sign, sample;
	int *p = x;
	int j;



	r[0] = seed + i;
	BLAKE_CHAR (r, 4, tmp);

	for(j=0; j<32; j++)
	{
		sign = tmp[j<<1]&1;
		sample = ((tmp[(j<<1)]>>1)&1)<<8;
		sample ^= tmp[(j<<1)+1];

		p[j] = CDT_TABLE[sample&0x1ff];
		p[j] = ((-sign)^p[j])+sign;

	}


}

int _KEM_Enc(int *C1, int *pA, int *pB, int *r, unsigned int *Msg, int MsgLen, unsigned int seed)
{

	int	i, j, k;
	int *M, *X, *Y, *t_A, *t_B;
	int	ret = 0, cnt=0;

	M = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));
	X = (int*)calloc(CRYPTO_v*CRYPTO_n, sizeof(int));
	Y = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	
	/* STEP 1 : Message matrix Generation */

	for (i = 0; i < CRYPTO_v*CRYPTO_k; i++)
	{
		M[i] ^= 0x8000; // 10
		M[i] ^= (((Msg[i >> 2] >> (24 - 8 * (i % 4))) & 0xff) << (CRYPTO_logq - CRYPTO_t));

	}

	/* STEP 3 : Error matrix generation */
	for (i = 0; i < CRYPTO_v*CRYPTO_n; i=i+32)
		Sample_CDT_hash(X+i, seed, i);

	seed = (-1)^seed;
	for (i = 0; i<CRYPTO_v*CRYPTO_k; i=i+32)
		Sample_CDT_hash(Y+i, seed, i);


	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pX = X + (CRYPTO_n * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pK = pA + (CRYPTO_n * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_n; ++j)
			{
				pX[j] += pRk * pK[j];
				pX[j] = pX[j] & CRYPTO_MASK;
			}
		}
	}


	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pY = Y + i;

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pK = pB + k;
			int pRk = pR[k];

				pY[0] += pRk * pK[0];
				pY[0] = pY[0] & CRYPTO_MASK;
		}
	}


	_MatADD(Y, Y, M, CRYPTO_v, CRYPTO_k);
	memcpy(C1, X, CRYPTO_v*CRYPTO_n * sizeof(int));
	memcpy(C1 + CRYPTO_v*CRYPTO_n, Y, CRYPTO_v*CRYPTO_k * sizeof(int));

	free(M);
	free(X);
	free(Y);

	return ret;

}


/* Key generation function : public and private keys */

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char rnd_t[CRYPTO_n];
	int i, j, k;
	int *pubA, *pubB, *priX;
	int ret = 0;
	int cnt = 0;


	pubA = (int*)calloc(CRYPTO_m * CRYPTO_n, sizeof(int));
	pubB = (int*)calloc(CRYPTO_m, sizeof(int));
	priX = (int*)calloc(CRYPTO_n, sizeof(int));
	
	randombytes(rnd_t, CRYPTO_n);
	
	/* Public Key A Generation */
	for (i = 0; i < CRYPTO_m *CRYPTO_n; i++)
		pubA[i] = random_modq();


	for (i = 0; i < CRYPTO_n; i++)
		priX[i] = ((rnd_t[i] % 3 + 1) - 2);

	for (i = 0; i < CRYPTO_m; i++)
		pubB[i] = Sample_CDT_NOSEED();



	/* Public Key B Generation */
	for (i = 0; i < CRYPTO_m; ++i)
	{
		int* A = pubA + CRYPTO_n * i;
		int* B = pubB + i;

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pk = priX + k;
			int A_ik = A[k];

				B[0] += A_ik * pk[0];
				B[0] = B[0] & 0xffffff;

		}
	}


	_BINT_to_OS(pk, pubA, (CRYPTO_m *CRYPTO_n) << 2);
	_BINT_to_OS(pk+ ((CRYPTO_m *CRYPTO_n) << 2), pubB, (CRYPTO_m) << 2);
	_BINT_to_OS(sk, priX, (CRYPTO_n) << 2);
	memcpy(sk+(CRYPTO_n<<2),pk,CRYPTO_PUBLICKEYBYTES);



err:
	free(pubA);
	free(pubB);
	free(priX);

	return ret;
}


/* CPA encryption module for CCA.KEM */



/* CPA decryption module for CCA.KEM */
int _KEM_Dec(unsigned int *Msg, int *pPriKey, int *pCipher)
{

	int i, j, k, *MP;
	int MsgByteLen;
	int ret = 0;
	int cnt=0;

	MP = (int*)calloc(CRYPTO_v, sizeof(int));

	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pX = pCipher + (CRYPTO_n * i);
		int* pM = MP + i;

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pK = pPriKey + k;
			int pXk = pX[k];

			pM[0] += pXk * pK[0];
			pM[0] = pM[0] & CRYPTO_MASK;

		}
	}


	for (i = 0; i < CRYPTO_v; i++)
	{

		MP[i] = (pCipher[i + CRYPTO_v*CRYPTO_n] - MP[i])& CRYPTO_MASK;
		_dropBits(MP[i], MP[i]);
	}

	for (i = 0; i < 8; i++)
	{
		Msg[i] = ((unsigned int)MP[(i << 2)] & 0xff) << 24;
		Msg[i] ^= ((unsigned int)MP[(i << 2) + 1] & 0xff) << 16;
		Msg[i] ^= ((unsigned int)MP[(i << 2) + 2] & 0xff) << 8;
		Msg[i] ^= ((unsigned int)MP[(i << 2) + 3] & 0xff);

	}

	free(MP);
	return ret;
}

/* CCA KEM encapsulation scheme */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
	unsigned int delta[9], tmp[16];
	unsigned int *KeyIn;
	unsigned int seed_in;
	unsigned char rnd[32];
	unsigned char e_input[48];
	int *pubA, *pubB, *pCipher;
	int i, KLen, CLen;
	int *r;
	int ret = 0;


	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;


	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));
	pubA = (int*)calloc(CRYPTO_m * CRYPTO_n, sizeof(int));
	pubB = (int*)calloc(CRYPTO_m, sizeof(int));
	pCipher = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k)+8, sizeof(int));

	_OS_to_BINT(pubA, pk, CRYPTO_m * CRYPTO_n);
	_OS_to_BINT(pubB, pk+((CRYPTO_m * CRYPTO_n)<<2), CRYPTO_m);




	/* STEP 1 : Select random 256 bit sizeof v*k */
	randombytes(rnd, 32);

	_OS_to_BINT(delta, rnd, 8);


	/* STEP 2 : r=G(delta), C_1=Enc(delta) */

	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);
	memset(e_input, 0, 48);
	e_input[0] =(seed_in&0xff000000)>>24;
	e_input[1] =(seed_in&0x00ff0000)>>16;
	e_input[2] =(seed_in&0x0000ff00)>>8;
	e_input[3] =(seed_in&0xff);
	randombytes_init (e_input, NULL, 256);
	_KEM_Enc(pCipher, pubA, pubB, r, delta, 32 << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);


	memcpy(pCipher + CRYPTO_v*(CRYPTO_n + CRYPTO_k), tmp, 8 * sizeof(int));

	_BINT_to_OS(ct, pCipher, (CLen) << 2);

	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_OS(KeyIn, KLen , ss);


	free(r);
	free(KeyIn);
	free(pubA);
	free(pubB);
	free(pCipher);

	return ret;
}



/* CCA KEM decapsulation scheme */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
	unsigned int delta[9], tmp[8];
	unsigned int seed_in;
	unsigned int *KeyIn;
	unsigned char e_input[48];
	int *r, *C_1, *pCipher, *priX, *pubA, *pubB;
	int i, KLen, CLen;
	int ret = 0;


	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int*));
	C_1 = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k), sizeof(int*));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));
	pCipher = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8, sizeof(int));
	priX = (int*)calloc(CRYPTO_n, sizeof(int));
	pubA = (int*)calloc(CRYPTO_m * CRYPTO_n, sizeof(int));
	pubB = (int*)calloc(CRYPTO_m, sizeof(int));


	_OS_to_BINT(pCipher, ct, CLen);
	_OS_to_BINT(priX, sk, CRYPTO_n);
	_OS_to_BINT(pubA, sk+(CRYPTO_n<<2), CRYPTO_m * CRYPTO_n);
	_OS_to_BINT(pubB, sk+((CRYPTO_m*CRYPTO_n+CRYPTO_n)<<2), CRYPTO_m);


	/* STEP 1 : Compute delta */
	_KEM_Dec(delta, priX, pCipher);

	/* STEP 2 : Compute r=G(delta) */
	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);

	memset(e_input, 0, 48);
	e_input[0] =(seed_in&0xff000000)>>24;
	e_input[1] =(seed_in&0x00ff0000)>>16;
	e_input[2] =(seed_in&0x0000ff00)>>8;
	e_input[3] =(seed_in&0xff);

	randombytes_init (e_input, NULL, 256);

	_KEM_Enc(C_1, pubA, pubB, r, delta, CRYPTO_delta << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);

	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_OS(KeyIn, KLen, ss);

err:
	memset(delta, 0, CRYPTO_delta);

	free(r);
	free(C_1);
	free(KeyIn);
	free(pCipher);
	free(priX);
	free(pubA);
	free(pubB);

	return ret;




}
