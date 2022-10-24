EXE    := detector dummy
CFLAGS := -std=c99 -Wall -Werror -O0

.PHONY: all clean

all: $(EXE)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(EXE) *.o
