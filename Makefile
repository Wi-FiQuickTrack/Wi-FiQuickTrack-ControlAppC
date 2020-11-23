# Type is laptop or openwrt
TYPE = laptop
# Role is dut or platform
ROLE = dut

OBJS = main.o eloop.o indigo_api.o indigo_packet.o utils.o wpa_ctrl.o
CFLAGS += -g

ifeq ($(TYPE),laptop)
CC = gcc
else
#CC = /openwrt/QCA_Sniffer_11ax/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-5.2.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-gcc
#LD = /openwrt/QCA_Sniffer_11ax/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-5.2.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-ld
CC = /openwrt/QCA_Sniffer_11ax/qsdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-5.2.0_musl-1.1.16/bin/aarch64-openwrt-linux-gcc
LD = /openwrt/QCA_Sniffer_11ax/qsdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-5.2.0_musl-1.1.16/bin/aarch64-openwrt-linux-ld
CFLAGS += -D_OPENWRT_
endif

ifeq ($(ROLE),dut)
OBJS += indigo_api_callback_dut.o
else
OBJS += indigo_api_callback_tp.o vendor_specific.o
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
endif

all: app

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

app: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf app *.o
