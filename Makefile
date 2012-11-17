CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c99 -O3 -D_XOPEN_SOURCE=600
LDFLAGS = -O3
EXEC    = proxy
SRC     = $(wildcard *.c)
OBJ     = $(SRC:.c=.o)

all: $(EXEC)

$(EXEC): $(OBJ)
	gcc $(LDFLAGS) $(OBJ) -o $(EXEC)

%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) $(OBJ)
