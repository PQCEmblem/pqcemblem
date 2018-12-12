# EMBLEM and R.EMBLEM




EMBLEM and R.EMBLEM is a post-quantum cryptographic algorithm based on (Ring) Learning with Errors ((R)LWE) problem written in C


## Contents

* [`KAT`](KAT/): Known Answer Test (KAT) files for the KEM.
* [`Optimized_Implementation`](Optimized_Implementation/): Optimized implementation of the EMBLEM and R.EMBLEM
* [`Reference_Implementation`](Reference_Implementation/): Reference implementation of the EMBLEM and R.EMBLEM
* [`Additional_Implementation`](Additional_Implementation/): Additional implementation of the EMBLEM and R.EMBLEM
* `EMBLEM_t4`: Source code for the EMBLEM when the message is split into 4 bits
* `EMBLEM_t8`: Source code for the EMBLEM when the message is split into 8 bits
* `R_EMBLEM_t1`: Source code for the R.EMBLEM when the message is split into 1 bit
* `R_EMBLEM_t2`: Source code for the R.EMBLEM when the message is split into 2 bits
 

## Main Features

- Supports IND-CCA secure key encapsulation mechanism.
- Support for Linux OS using GNU GCC.     
- Includes Known Answer Tests (KATs).
- `Additional_Implementation` is an implementation of EMBLEM and R.EMBLEM using the compressed private key. 


## Implementation

OpenSSL must be installed before building EMBLEM and R.EMBLEM

### Instructions for Linux:

- Define parameters by typing '#define xxx' on param.h as given in below ('Parameter Sets')
- Type 

  ```sh
  $ make
  ```

## Parameter Sets
Both EMBLEM and R.EMBLEm paremeters can be configured by editing 'params.h'.
Below are parameter sets used in each folder.

* EMBLEM_t4 (m, n, k, v)  
  `#define ONE`: (1,008, 824, 2, 32)  
  `#define TWO`: (1,008, 824, 4, 16)  
  `#define THREE`: (1,008, 824, 8, 8)  
  `#define FOUR`: (1,008, 824, 16, 4)  
  `#define FIVE`: (1,008, 824, 32, 2)  
  `#define SIX`: (1,008, 824, 64, 1)  

  `#define ONE_TWO`: (1,016, 784, 2, 32)  
  `#define TWO_TWO`: (1,016, 784, 4, 16)  
  `#define THREE_TWO`: (1,016, 784, 8, 8)  
  `#define FOUR_TWO`: (1,016, 784, 16, 4)  
  `#define FIVE_TWO`: (1,016, 784, 32, 2)  
  `#define SIX_TWO`: (1,016, 784, 64, 1)  
  
* EMBLEM_t8 (m, n, k, v)  
  `#define ONE`: (1,184, 1,024, 1, 32)  
  `#define TWO`: (1,184, 1,024, 2, 16)  
  `#define THREE`: (1,184, 1,024, 4, 8)  
  `#define FOUR`: (1,184, 1,024, 8, 4)  
  `#define FIVE`: (1,184, 1,024, 16, 2)  
  `#define SIX`: (1,184, 1,024, 32, 1)  

  `#define ONE_TWO`: (1,144, 984, 1, 32)  
  `#define TWO_TWO`: (1,144, 984, 2, 16)  
  `#define THREE_TWO`: (1,144, 984, 4, 8)  
  `#define FOUR_TWO`: (1,144, 984, 8, 4)  
  `#define FIVE_TWO`: (1,144, 984, 16, 2)  
  `#define SIX_TWO`: (1,144, 984, 32, 1)  

* R.EMBLEM_t1 (n, q, t)  
  `#define R_14_1`: (1,024, 12289, 1)  
  `#define R_14_2`: (1,024, 12289, 1)  

* R.EMBLEM_t2 (n, q, t)  
  `#define R_16_1`: (1,024, 40961, 2)  
  `#define R_16_2`: (1,024, 40961, 2)  






