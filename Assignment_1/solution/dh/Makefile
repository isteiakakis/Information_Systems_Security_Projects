CC=gcc
CFLAGS=-g3 -Wall -lm

SRC=dh_assign_1.c
OBJ=dh_assign_1.o
BIN=dh_assign_1

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lm -lgmp

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ) $(BIN)
