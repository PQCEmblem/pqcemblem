
#include "encrypt.h"
#include "ntt.h"
#include "ntt_const.h"
#include "blake2_locl.h"
#include "blake2_impl.h"
#include <openssl/sha.h>
#include <immintrin.h>
#include <time.h>

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


double time_keygen = 0, time_enc = 0, time_dec = 0;

int fmodq_enc(int x)
{
	double c = x%CRYPTO_R_q;
	if (c < 0) c = c + CRYPTO_R_q;

	return (int)c;

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

void BLAKE_CHAR (unsigned int *Msg, unsigned int MLen, unsigned char *Digest)
{
	unsigned char *M_tmp;


	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	BLAKE2b(Digest, M_tmp, MLen);


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



void CRYPTO_R_pub_init(CRYPTO_R_pub_t pPubKey)
{
	pPubKey->A = (int*)calloc(CRYPTO_R_n, sizeof(int));
	pPubKey->B = (int*)calloc(CRYPTO_R_n, sizeof(int));

}


void CRYPTO_R_pub_clear(CRYPTO_R_pub_t pPubKey)
{
	free(pPubKey->A);
	free(pPubKey->B);

}

char CDT_TABLE[512]=
{
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
	20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20
};
/* Gaussain sampling from CDT table */
int Sample_CDT()
{
	int r, sign, sample;
	int i;

	sign = rand() & 1;
	sample = CDT_TABLE[rand() & 0xff];


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



/* Key generation function : public and private keys are in NTT domain */
int CRYPTO_R_KeyGen(CRYPTO_R_pub_t pPubKey, int *pPriKey)
{
	int i, tmp[8];

	/* STEP 1 : Choose a, x, e */
	for (i = 0; i < CRYPTO_R_n; i++)
		pPubKey->A[i] = ((rand() & 0xff) | ((rand() & 0xf) << 8))%CRYPTO_R_q;


	for (i = 0; i < CRYPTO_R_n; i++)
		pPriKey[i] = (((rand() % CRYPTO_RGen) + 1) - CRYPTO_Rm);

	for (i = 0; i < CRYPTO_R_n; i++)
		pPubKey->B[i] = Sample_CDT(); 

	/* STEP 2 : b = a*x+e */

	NTT(pPubKey->A, CRYPTO_R_NTT, CRYPTO_R_n);
	NTT(pPriKey, CRYPTO_R_NTT, CRYPTO_R_n);
	NTT(pPubKey->B, CRYPTO_R_NTT, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_n; i++) {

  
		pPubKey->B[i] = fmodq_enc((long long int)(pPubKey->A[i] * pPriKey[i] + pPubKey->B[i]));
	}

	return 0;
}

/* CPA encryption module for CCA.KEM */
int _R_KEM_Enc(int *C, unsigned int *delta, CRYPTO_R_pub_t pPubKey, int *r, int seed)
{
	int *m_hat, *e1, *e2;
	int i;
	int tmp1[CRYPTO_R_n], tmp2[CRYPTO_R_n];

	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e1 = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e2 = (int*)calloc(CRYPTO_R_n, sizeof(int));

	/* STEP 1 : R_encode */
	for (i = 0; i < CRYPTO_R_msg; i++)
	{

		m_hat[i] ^= 0x1000;
		m_hat[i] ^= ((delta[i >> 4] >> (30 - 2*(i % 16))) & 0x3) << 13;

	}

	for (i = 0; i < CRYPTO_R_n; i=i+32)
		Sample_CDT_hash(e1+i, seed, i);

	seed = (-1)^seed;

	for (i = 0; i < CRYPTO_R_n; i=i+32)
		Sample_CDT_hash(e2+i, seed, i);

	NTT(r, CRYPTO_R_NTT, CRYPTO_R_n);

	/* STEP 3 : C1 = R^T x A + E_1 */

	for (i = 0; i < CRYPTO_R_n; i++) {
		tmp1[i] = ((long long int)(pPubKey->A[i] * r[i])) % CRYPTO_R_q;

	}

	INTT(tmp1, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_n; i++)
	{
		e1[i] = (tmp1[i] + e1[i]) % CRYPTO_R_q;
		if (e1[i]<0) e1[i] += CRYPTO_R_q;

	}

	/* STEP 4 : C2 = R^T x B + E_1 + M */

	for (i = 0; i < CRYPTO_R_n; i++) {
		tmp2[i] = ((long long int)(pPubKey->B[i] * r[i])) % CRYPTO_R_q;

	}

	INTT(tmp2, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_n; i++)
	{
		e2[i] = (e2[i] + tmp2[i]) % CRYPTO_R_q;
		e2[i] = (e2[i] + m_hat[i]) % CRYPTO_R_q;
		if (e1[i]<0) e1[i] += CRYPTO_R_q;

	}


	/* STEP 5 : C = C1 || C2 */
	memcpy(C, e1, CRYPTO_R_n * sizeof(int));
	memcpy(C + (CRYPTO_R_n), e2, CRYPTO_R_msg * sizeof(int));

	free(m_hat);
	free(e1);
	free(e2);

	return 0;
}


/* CPA decryption module for CCA.KEM */
int _R_KEM_dec(unsigned int *delta, int *C, int *pPriKey)
{
	int *d, *m_hat, *C_cpy;
	int i;

	d = (int*)calloc(CRYPTO_R_n, sizeof(int));
	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	C_cpy = (int*)calloc(CRYPTO_R_n, sizeof(int));

	NTT_new(C_cpy, C, CRYPTO_R_NTT, CRYPTO_R_n);


	for (i = 0; i < CRYPTO_R_n; i++) {
		d[i] = ((long long int)(C_cpy[i] * pPriKey[i])) % CRYPTO_R_q;

	}

	INTT(d, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_msg; i++)
	{

		m_hat[i] = (C[i + CRYPTO_R_n] - d[i]) % CRYPTO_R_q;
		if (m_hat[i] < 0) m_hat[i] += CRYPTO_R_q;

	}

	memset(delta, 0, 8 * sizeof(int));

	for (i = 0; i < CRYPTO_R_msg; i++)
	{
		delta[i >> 4] ^= ((m_hat[i] >> 13) & 0x3) << (30 - 2*(i % 16));

	}

	free(d);
	free(m_hat);
	free(C_cpy);
	return 0;
}

/* Generates seed and random number in {-1, 0, 1} from delta */
unsigned int _R_KEM_GenTrinary(int *r, unsigned int *delta)
{
	unsigned int d_tmp[9];
	unsigned int tmp[16];
	int cnt = 0, iter=0;
	int j;

	memcpy(d_tmp, delta, 8 * sizeof(int));
	memset(tmp, 0, 16 * sizeof(int));

	while (cnt < CRYPTO_R_n)
	{
		BLAKE_INT(d_tmp, 32, tmp);
		for (j = 0; j < 16; j++)
		{
			while ((tmp[j] != 0) && (cnt<CRYPTO_R_n))
			{
				r[cnt] = (((tmp[j] % CRYPTO_RGen) + 1) - CRYPTO_Rm);
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

/* CCA KEM encapsulation scheme */
int CRYPTO_R_Encap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey)
{
	unsigned int delta[9], tmp[8];
	unsigned int seed, KLen;
	unsigned int *K_tmp;
	int *r, *C_KEM;
	int i;

	r = (int*)calloc(CRYPTO_R_n, sizeof(int));
	C_KEM = (int*)calloc(CRYPTO_R_n + CRYPTO_R_msg, sizeof(int));
	K_tmp = (unsigned int*)calloc(CRYPTO_R_n + CRYPTO_R_msg + 16, sizeof(unsigned int));

	KLen = CRYPTO_R_n + CRYPTO_R_msg + 16;
	KLen = KLen << 2;

	/* STEP 1 : Select delta */
	for (i = 0; i < 8; i++)
	{
		delta[i] = (rand() & 0xff) | ((rand() & 0xff) << 8) | ((rand() & 0xff) << 16) | ((rand() & 0xff) << 24);
	}

	/* STEP 2 : Generate ciphertext */
	seed = _R_KEM_GenTrinary(r, delta);
	_R_KEM_Enc(C_KEM, delta, pPubKey, r, seed);

	/* STEP 3 : Generate hash */
	delta[8] = 0x02000000;
	SHA256_INT(delta, 33, tmp);

	// C = C1 || H(delta)
	memcpy(C, C_KEM, (CRYPTO_R_n + CRYPTO_R_msg) * sizeof(unsigned int));
	memcpy(C + (CRYPTO_R_n + CRYPTO_R_msg), tmp, 8 * sizeof(unsigned int));

	/* STEP 4 : Generate key */
	// K_tmp = delta || C
	memcpy(K_tmp, delta, 8 * sizeof(unsigned int));
	memcpy(K_tmp + 8, C, (CRYPTO_R_n + CRYPTO_R_msg + 8) * sizeof(unsigned int));


	SHA256_INT(K_tmp, KLen, K);

	free(r);
	free(C_KEM);
	free(K_tmp);

	return 0;
}

/* CCA KEM decapsulation scheme */
int CRYPTO_R_Decap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey, int *pPriKey)
{
	unsigned int delta[9], tmp[8];
	unsigned int seed, KLen;
	unsigned int *K_tmp;
	int *C_tmp, *r;
	int ret;

	C_tmp = (int*)calloc(CRYPTO_R_n + CRYPTO_R_msg, sizeof(int));
	r = (int*)calloc(CRYPTO_R_n, sizeof(int));
	K_tmp = (unsigned int*)calloc(CRYPTO_R_n + CRYPTO_R_msg + 16, sizeof(unsigned int));

	KLen = CRYPTO_R_n + CRYPTO_R_msg + 16;
	KLen = KLen << 2;

	/* STEP 1 : Decrypt and obtain delta */
	_R_KEM_dec(delta, C, pPriKey);

	/* STEP 2 : Generate r and seed from delta */
	seed = _R_KEM_GenTrinary(r, delta);

	/* STEP 3 : Encrypt */
	_R_KEM_Enc(C_tmp, delta, pPubKey, r, seed);


	delta[8] = 0x02000000;
	SHA256_INT(delta, 33, tmp);

	/* STEP 4 : Generate key*/
	memcpy(K_tmp, delta, 8 * sizeof(unsigned int));
	memcpy(K_tmp + 8, C, (CRYPTO_R_n + CRYPTO_R_msg + 8) * sizeof(unsigned int));

	SHA256_INT(K_tmp, KLen, K);

	free(C_tmp);
	free(r);
	free(K_tmp);

	return 0;
}



/* Test function for CCA */
void CRYPTO_TEST_CCA(int iter)
{
	int pPriKey[CRYPTO_R_n], C[CRYPTO_R_n + CRYPTO_R_msg], C_CCA[CRYPTO_R_n + CRYPTO_R_msg + 8];
	unsigned int Msg[8] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
	unsigned int MsgPrime[8];
	unsigned int K[8], KPrime[8];

	int i, j;

	CRYPTO_R_pub_t pPubKey;
	CRYPTO_R_pub_init(pPubKey);

time_keygen=0; time_enc=0; time_dec=0;
	/* R-CCA Test */
	for (i = 0; i < iter; i++)
	{
		START_WATCH;	
		CRYPTO_R_KeyGen(pPubKey, pPriKey);
		STOP_WATCH;
		time_keygen+=sec;
	}

	for (i = 0; i < iter; i++)
	{
		START_WATCH;	
		CRYPTO_R_Encap(K, C_CCA, pPubKey);
		STOP_WATCH;
		time_enc+=sec;
	}

	for (i = 0; i < iter; i++)
	{
		START_WATCH;	
		CRYPTO_R_Decap(KPrime, C_CCA, pPubKey, pPriKey);
		STOP_WATCH;
		time_dec+=sec;
	}

	

	printf("\t Keygen Time  : %.5f ms \n", ((time_keygen / iter) * 1000));
	printf("\t Encap Time  : %.5f ms \n", ((time_enc / iter) * 1000));
	printf("\t decap Time  : %.5f ms \n", ((time_dec/ iter) * 1000));

	CRYPTO_R_pub_clear(pPubKey);

}


void main()
{

	printf("=========== CURRENT PARAMETERS ===========\n");
	printf("\t n: %d \n", CRYPTO_R_n);
	printf("\t q: %d \n", CRYPTO_R_q);
	printf("\t k: %d \n", CRYPTO_R_k);
	printf("\t t: %d \n", CRYPTO_R_t);
	printf("\t RGen: %d \n", CRYPTO_RGen);
	printf("==========================================\n");

	CRYPTO_TEST_CCA(10000);
}
