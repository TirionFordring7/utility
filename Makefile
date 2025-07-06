CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -pedantic
TARGET  = utility

$(TARGET): utility.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)
