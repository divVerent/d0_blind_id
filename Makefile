all: blind_id

OBJECTS = d0.o d0_blind_id.o d0_iobuf.o d0_bignum-gmp.o sha1.o main.o

blind_id: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^
clean:
	$(RM) blind_id $(OBJECTS)

CFLAGS += -Wall -Wextra
CPPFLAGS += -I/opt/gmp/include
LDFLAGS += -L/opt/gmp/lib -Wl,-rpath,/opt/gmp/lib -lgmp -lm -lrt -s -O3
