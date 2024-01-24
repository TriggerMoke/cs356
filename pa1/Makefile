CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = cipher
SRC = cipher.c
PACKAGE = PA1_Aidan_Michalos.tar.gz
FILES_TO_PACKAGE = $(SRC) Makefile README.md key.txt sample.txt

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

package:
	tar -czvf $(PACKAGE) $(FILES_TO_PACKAGE)

clean:
	rm -f $(TARGET) $(PACKAGE)