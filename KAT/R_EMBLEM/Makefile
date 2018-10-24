
OPENSSL_DIR=/usr

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -mavx2 -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl


all:
	#$(CC) $(CFLAGS) -c kem.c rng.c $(LDFLAGS)
	#$(CC) $(CFLAGS) -o kem.o rng.o $(LDFLAGS)
	$(CC) $(CFLAGS) -c PQCgenKAT_kem.c kem.c rng.c blake2b.c blake2s.c api.h $(LDFLAGS)
	$(CC) $(CFLAGS) -o PQCgenKAT_kem PQCgenKAT_kem.o kem.o blake2b.o blake2s.o rng.o $(LDFLAGS)

	
