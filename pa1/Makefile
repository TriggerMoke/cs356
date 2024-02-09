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

block:
	./$(TARGET) B sample.txt sample_BE.txt key.txt E
	./$(TARGET) B sample_BE.txt sample_BD.txt key.txt D

stream:
	./$(TARGET) S sample.txt sample_SE.txt key.txt E
	./$(TARGET) S sample_SE.txt sample_SD.txt key.txt D