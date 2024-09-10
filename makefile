# Makefile to compile the PCAP reader program

CC = gcc
CFLAGS = -Wall -g

TARGET = read_pcap.out
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) *.o
