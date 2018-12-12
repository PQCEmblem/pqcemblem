#include "ntt.h"
#include "param.h"
#include <math.h>
#include <immintrin.h>


int fmodq(int x)
{
	double c = x%CRYPTO_R_q;
	if (c < 0) c = c + CRYPTO_R_q;

	return (int)c;

}

/*
int Lreduc(int x)

{

	double c = x%CRYPTO_R_q;
	if (c < 0) c = c + CRYPTO_R_q;

	return (int)c;


}

int Lreduc_mul(int x)
{
	double c = x%CRYPTO_R_q;
	if (c < 0) c = c + CRYPTO_R_q;

	return (int)c;

}
*/


/* Polynomial multiplication in NTT domain :: c=a*b */
void pmul(int *a, int *b, int *c, int N)
{ 
	unsigned int i;

	for (i = 0; i < N; i++) {
		c[i] = ((long long int)(a[i] * b[i])) % CRYPTO_R_q;

	}
}

/* Polynomial multiplication and addition in NTT domain :: c=a*b+c */
void pmuladd(int *a, int *b, int *c, int *d, int N)
{ 
	unsigned int i;



	for (i = 0; i < N; i++) {

  
		d[i] = fmodq((long long int)(a[i] * b[i] + c[i]));
	}
}

/* Polynomial addition :: c=a+b */
void padd(int *a, int *b, int *c, int p, int N)
{  
	unsigned int i;

	for (i = 0; i < N; i++)
	{
		c[i] = (a[i] + b[i]) % p;
		if (c[i]<0) c[i] += p;

	}
}

void NTT(int *a, const int *psi, int N)
{
	int t;
	int j1, j2, i, j, m;
	int S, U, V;

	t = N;

	for (m = 1; m < N; m = m << 1)
	{
		t = t >> 1;
		for (i = 0; i < m; i++)
		{
			j1 = 2 * i*t;
			j2 = j1 + t - 1;
			S = psi[m + i];
			for (j = j1; j <= j2; j++)
			{
				U = a[j];
				V = fmodq(a[j + t] * S);
				a[j] = fmodq((U + V));
				a[j + t] = fmodq(U - V);
			}

		}
	}

	for (j = 0; j < N; j++)
	{
		a[j] = fmodq(a[j]);
	}

}

/* NTT function that preserves input */
void NTT_new(int *aout, int *a, const int *psi, int N)
{
	int t;
	int j1, j2, i, j, m;
	int S, U, V;
	int *a_tmp;
	t = N;

	a_tmp = (int*)calloc(CRYPTO_R_n, sizeof(int));
	memcpy(a_tmp, a, CRYPTO_R_n * sizeof(int));
	for (m = 1; m < N; m = m << 1)
	{
		t = t >> 1;
		for (i = 0; i < m; i++)
		{
			j1 = 2 * i*t;
			j2 = j1 + t - 1;
			S = psi[m + i];
			for (j = j1; j <= j2; j++)
			{
				U = a_tmp[j];

				V = fmodq(a_tmp[j + t] * S);
				a_tmp[j] = fmodq((U + V));
				a_tmp[j + t] = fmodq(U - V);
			}

		}
	}


	memcpy(aout, a_tmp, CRYPTO_R_n * sizeof(int));
	free(a_tmp);

}

void INTT(int* a, const int *psi_inv, int Ninv, int N)
{
	unsigned int t, h;
	unsigned int j1, j2, i, j, m;
	int S, U, V;

	t = 1;
	for (m = N; m > 1; m = m >> 1)
	{
		j1 = 0;
		h = m >> 1;
		for (i = 0; i < h; i++)
		{
			j2 = j1 + t - 1;
			S = psi_inv[h + i];

			for (j = j1; j <= j2; j++)
			{
				U = a[j];
				V = a[j + t];
				a[j] = fmodq(U + V);
				a[j + t] = fmodq((U - V)*S);

			}
			j1 = j1 + (t << 1);
		}
		t = t << 1;

	}

	for (j = 0; j < N; j++)
	{

		a[j] = fmodq(a[j] * Ninv);
		if (a[j] < 0) a[j] += CRYPTO_R_q;
	}

}
