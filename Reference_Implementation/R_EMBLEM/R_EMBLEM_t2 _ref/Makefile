OPENSSL_DIR=/usr

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -mavx2 -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl


all:

	$(CC) $(CFLAGS) -c encrypt.c blake2b.c blake2s.c ntt.c ntt.h ntt_const.h $(LDFLAGS)
	$(CC) $(CFLAGS) -o R_EMBLEM_t2_ref encrypt.o blake2b.o blake2s.o ntt.o $(LDFLAGS)
