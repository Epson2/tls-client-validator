CC=clang
CFLAGS=-Wall -Wextra -O2 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

TARGET=tls_client
SRC=tls_client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)