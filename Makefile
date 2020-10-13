CC = gcc
OBJS = main.o eloop.o indigo_api.o indigo_api_callback.o indigo_packet.o utils.o
CFLAGS += -g

all: app

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

app: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf app *.o
