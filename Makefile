CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -DPQC_FIXED_TEST_KEY=1 -I. -Iinc -Iinc/core -Iinc/pqc -Isrc/db -I../include -Isrc/pqc/include -Wall -O2 -mcmodel=medium $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -Wl,-rpath,'$$ORIGIN/lib' -lelf -lz -lpthread \
          ./lib/libxdp.so.1 -lbpf -lpq ./lib/libscrypt.so

BPF_CFLAGS     = -O2 -target bpf -g -DNE_BPF
KERNEL_HEADERS = /usr/include

LIB_DIR = lib
TARGET  = network-encryptor

PQC_SRCS = $(filter-out %-old.c,$(wildcard src/pqc/*.c))

CORE_SRCS = $(wildcard src/core/runtime/*.c) \
            $(wildcard src/core/profile/*.c) \
            $(wildcard src/core/interface/*.c) \
            $(wildcard src/core/dataplane/*.c) \
            $(wildcard src/core/crypto/*.c) \
            $(wildcard src/core/wan/*.c)

APP_SRC = main.c \
          $(CORE_SRCS) \
          $(PQC_SRCS)
APP_OBJ = $(APP_SRC:.c=.o)

DB_SRC = src/db/db_config.c \
         src/db/db_env.c \
         src/db/db_runtime.c \
         src/db/vault.c
DB_OBJ = $(DB_SRC:.c=.o)

BPF_OBJ = $(LIB_DIR)/lan.o \
          $(LIB_DIR)/wan.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

$(TARGET): $(APP_OBJ) $(DB_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


$(LIB_DIR)/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I../include -c $< -o $@

clean:
	rm -rf network-encryptor src/*.o src/core/*/*.o src/pqc/*.o \
		src/db/*.o *.o $(BPF_OBJ)
