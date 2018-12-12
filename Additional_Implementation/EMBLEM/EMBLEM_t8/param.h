#pragma once

#include <stdlib.h>
#include <stdio.h>

#define TWO

#define CRYPTO_OK 0
#define CRYPTO_ERROR 1


#ifdef ONE

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
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif
#ifdef TWO

#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 2
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 16
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef THREE

#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 4
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 8
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FOUR

#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 8
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 4
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FIVE

#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 16
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 2
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef SIX

#define CRYPTO_m 1184
#define CRYPTO_n 1024
#define CRYPTO_k 32
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 1
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 3
#define CRYPTO_RM 2
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif


#ifdef ONE_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 1
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 32
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif
#ifdef TWO_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 2
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 16
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef THREE_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 4
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 8
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FOUR_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 8
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 4
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FIVE_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 16
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 2
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef SIX_TWO

#define CRYPTO_m 1144
#define CRYPTO_n 984
#define CRYPTO_k 32
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 1
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_MASK 0xffffff
#define CRYPTO_RGen 5
#define CRYPTO_RM 3
//#define CRYPTO_MASK 0x1fffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif
#define _MatTrans(r, x, row_x, column_x)\
{\
int _i, _j;\
for(_i=0;_i<row_x;_i++)\
{\
for(_j=0;_j<column_x;_j++)\
{\
r[row_x*_j+_i]=x[_i*column_x+_j];\
}\
}\
}

#define _MatADD(r, x, y, row_x, column_x)\
{\
int _i;\
for(_i=0; _i<row_x*column_x;_i++)\
{\
r[_i]=(x[_i]+y[_i])&CRYPTO_MASK;\
}\
}

#define _MatSUB(r, x, y, row_x, column_x)\
{\
int _i;\
for(_i=0; _i<row_x*column_x;_i++)\
{\
r[_i]=(x[_i]-y[_i])&CRYPTO_MASK;\
}\
}

#define _dropBits(dx, x)\
{\
int _tmp=0;\
_tmp = x >> (CRYPTO_logq-CRYPTO_t);\
_tmp = _tmp & 0xff;\
dx = _tmp;\
}


typedef struct
{
	int *A;
	int *B;

}_CRYPTO_public_struct;

typedef _CRYPTO_public_struct CRYPTO_public_t[1];


