CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11

fim: fim.c
	$(CC) $(CFLAGS) -o fim fim.c

clean:
	rm -f fim

.PHONY: clean
