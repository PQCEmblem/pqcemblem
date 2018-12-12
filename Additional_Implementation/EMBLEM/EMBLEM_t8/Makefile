OPENSSL_DIR=/usr

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -funroll-all-loops -march=native -mavx2 -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl


all:

	$(CC) $(CFLAGS) -c encrypt.c blake2b.c blake2s.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o EMBLEM_t8_opt encrypt.o blake2b.o blake2s.o $(LDFLAGS)
