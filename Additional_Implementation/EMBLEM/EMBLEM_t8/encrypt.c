
#include <string.h>
#include "param.h"
#include <openssl/sha.h>
#include <immintrin.h>
#include "blake2_locl.h"
#include "blake2_impl.h"
#include <time.h>
#include <x86intrin.h>
clock_t elapsed, start;
float sec;
#define START_WATCH \
{\
 elapsed = -clock(); \
}\

#define STOP_WATCH \
{\
 elapsed += clock();\
 sec = (float)elapsed/CLOCKS_PER_SEC;\
}\

#define PRINT_TIME(qstr) \
{\
 printf("\n[%s: %.5f s]\n",qstr,sec);\
}\


double time_keygen = 0, time_enc = 0, time_enc_avx = 0,time_dec = 0, time_hash=0, time_matmul=0;

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

void CRYPTO_public_init(CRYPTO_public_t pPubKey, int s1, int s2)
{
	pPubKey->A = (int*)calloc(s1, sizeof(int));
	pPubKey->B = (int*)calloc(s2, sizeof(int));

}

void CRYPTO_public_clear(CRYPTO_public_t pPubKey)
{
	free(pPubKey->A);
	free(pPubKey->B);
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


/* Key generation function : public and private keys */

int inline CRYPTO_KeyGen(CRYPTO_public_t pPubKey, int *pPriKey)
{
	int i, j, k;
	int ret = 0;
	int cnt = 0;
	int *pPriK;

	pPriK =(int*)calloc(CRYPTO_n*CRYPTO_k, sizeof(int));

	/* Public Key A Generation */
	for (i = 0; i < CRYPTO_m*CRYPTO_n; i++)
		pPubKey->A[i] = (rand() & 0xff) | ((rand() & 0xff) << 8);

	/* Generate 32byte private key */
	for (i = 0; i < 8; i++)
		pPriKey[i] = (rand() & 0xff) | ((rand() & 0xff) << 8) | ((rand() & 0xff) << 16) | ((rand() & 0xff) << 24);

	/* Expand to private key */
	_KEM_GenTrinary(pPriK, pPriKey, CRYPTO_n*CRYPTO_k);

	for (i = 0; i < CRYPTO_m*CRYPTO_k; i++)
		pPubKey->B[i] = Sample_CDT_NOSEED();


	/* Public Key B Generation */


	for (i = 0; i < CRYPTO_m; ++i)
	{
		int* A = pPubKey->A + CRYPTO_n * i;
		int* B = pPubKey->B + CRYPTO_k * i;

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pk = pPriK + CRYPTO_k * k;
			int A_ik = A[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				B[j] += A_ik * pk[j];
				B[j] = B[j] & CRYPTO_MASK;
			}
		}
	}

	free(pPriK);
	return ret;
}

/* CPA encryption module for CCA.KEM */
int _KEM_Enc(int *C1, CRYPTO_public_t pPubKey, int *r, unsigned int *Msg, int MsgLen, unsigned int seed)
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
			int* pK = pPubKey->A + (CRYPTO_n * k);
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
		int* pY = Y + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pK = pPubKey->B + (CRYPTO_k * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pY[j] += pRk * pK[j];
				pY[j] = pY[j] & CRYPTO_MASK;
			}
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


/* CPA decryption module for CCA.KEM */
int _KEM_Dec(unsigned int *Msg, int *pPriKey, int *pCipher)
{

	int i, j, k, *MP;
	int MsgByteLen;
	int ret = 0;
	int cnt=0;

	MP = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pX = pCipher + (CRYPTO_n * i);
		int* pM = MP + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pK = pPriKey + (CRYPTO_k * k);
			int pXk = pX[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pM[j] += pXk * pK[j];
				pM[j] = pM[j] & CRYPTO_MASK;
			}
		}
	}


	for (i = 0; i < CRYPTO_v*CRYPTO_k; i++)
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
int CRYPTO_KEM_Encap(unsigned int *Key, int *pCipher, CRYPTO_public_t pPubKey)
{
	unsigned int delta[9], tmp[16];
	unsigned int *KeyIn;
	unsigned int seed_in;
	int i, KLen, CLen;
	int *r;
	int ret = CRYPTO_OK;


	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int*));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));



	/* STEP 1 : Select random 256 bit sizeof v*k */
	for (i = 0; i < 8; i++)
	{
		delta[i] = (rand() & 0xff) | ((rand() & 0xff) << 8) | ((rand() & 0xff) << 16) | ((rand() & 0xff) << 24);
	}


	/* STEP 2 : r=G(delta), C_1=Enc(delta) */

	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);

	_KEM_Enc(pCipher, pPubKey, r, delta, CRYPTO_delta << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);

	memcpy(pCipher + CRYPTO_v*(CRYPTO_n + CRYPTO_k), tmp, 8 * sizeof(int));


	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_INT(KeyIn, KLen << 2, Key);

	free(r);
	free(KeyIn);

	return ret;
}



/* CCA KEM decapsulation scheme */
int CRYPTO_KEM_Decap(unsigned int *Key, int *pCipher, CRYPTO_public_t pPubKey, int *pPriKey)
{
	unsigned int delta[8], tmp[8];
	unsigned int seed_in;
	unsigned int *KeyIn;
	int *r, *C_1, *pPriK;
	int i, KLen, CLen;
	int ret = CRYPTO_OK;

	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int*));
	C_1 = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k), sizeof(int*));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));
	pPriK =(int*)calloc(CRYPTO_n*CRYPTO_k, sizeof(int));

	/* Expand private key */
	_KEM_GenTrinary(pPriK, pPriKey, CRYPTO_n*CRYPTO_k);

	/* STEP 1 : Compute delta */
	_KEM_Dec(delta, pPriK, pCipher);

	/* STEP 2 : Compute r=G(delta) */
	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);

	_KEM_Enc(C_1, pPubKey, r, delta, CRYPTO_delta << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);



	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_INT(KeyIn, KLen << 2, Key);

	memset(delta, 0, CRYPTO_delta);

	free(r);
	free(C_1);
	free(KeyIn);
	free(pPriK);

	return ret;
}


/* Test function for CCA */
void CRYPTO_TEST_CCA(int iter)
{
	unsigned int Key[8];
	unsigned int KeyPrime[8];
	int i;
	int *pCipher;
	int *pPriKey;
	CRYPTO_public_t pPubKey;

	CRYPTO_public_init(pPubKey, CRYPTO_m*CRYPTO_n, CRYPTO_m*CRYPTO_k);

	pPriKey = (int*)calloc(CRYPTO_n*CRYPTO_k, sizeof(int));
	pCipher = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8, sizeof(int));

time_keygen=0; time_enc=0; time_dec=0;
	for (i = 0; i < iter; i++)
	{
		START_WATCH;
		CRYPTO_KeyGen(pPubKey, pPriKey);
		STOP_WATCH;
		time_keygen+=sec;
	}

	for (i = 0; i < iter; i++)
	{
		START_WATCH;
		CRYPTO_KEM_Encap(Key, pCipher, pPubKey);
		STOP_WATCH;
		time_enc+=sec;
	}

	for (i = 0; i < iter; i++)
	{
		START_WATCH;
		CRYPTO_KEM_Decap(KeyPrime, pCipher, pPubKey, pPriKey);
		STOP_WATCH;
		time_dec+=sec;
	}

	printf("\t Keygen Time  : %.5f ms \n", ((time_keygen / iter) * 1000));
	printf("\t Encap Time  : %.5f ms \n", ((time_enc / iter) * 1000));
	printf("\t decap Time  : %.5f ms \n", ((time_dec/ iter) * 1000));

	CRYPTO_public_clear(pPubKey);
	free(pPriKey);
	free(pCipher);

}




void main()
{

	printf("=========== CURRENT PARAMETERS ===========\n");
	printf("\t m: %d \n", CRYPTO_m);
	printf("\t n: %d \n", CRYPTO_n);
	printf("\t k: %d \n", CRYPTO_k);
	printf("\t v: %d \n", CRYPTO_v);
	printf("\t t: %d \n", CRYPTO_t);
	printf("\t logq: %d \n", CRYPTO_logq);
	printf("==========================================\n");

	CRYPTO_TEST_CCA(10000);
}
