# Type is laptop or openwrt
TYPE = laptop
# Role is dut or platform
ROLE = dut

OBJS = main.o eloop.o indigo_api.o indigo_packet.o utils.o wpa_ctrl.o
CFLAGS += -g

ifeq ($(TYPE),laptop)
CC = gcc
else
CC = arm-openwrt-linux-muslgnueabi-gcc
LD = arm-openwrt-linux-muslgnueabi-ld
CFLAGS += -DOPENWRT
endif

ifeq ($(ROLE),dut)
OBJS += indigo_api_callback_dut.o
else
OBJS += indigo_api_callback_tp.o
endif

all: app

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

app: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf app *.o
