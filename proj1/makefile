# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -g

all: Server/server Client/client

Server/server: Server/server.c
	$(CC) $(CFLAGS) -o Server/server Server/server.c

Client/client: Client/client.c
	$(CC) $(CFLAGS) -o Client/client Client/client.c

clean:
	rm -f Server/server Client/client
