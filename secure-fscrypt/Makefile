CFLAGS += -Wall -Wextra -O2

all: secure-fscryptctl

secure-fscryptctl: secure-fscryptctl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f secure-fscryptctl
