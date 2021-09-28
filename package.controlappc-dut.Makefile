include $(TOPDIR)/rules.mk

PKG_NAME:=controlappc-dut
PKG_RELEASE:=1.0.6

PKG_MAINTAINER:=WFA
PKG_LICENSE:=WFA

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_RELEASE)
PKG_BUILD_PARALLEL:=1

TARGET_LDFLAGS_C:=$(TARGET_LDFLAGS)

STAMP_CONFIGURED:=$(STAMP_CONFIGURED)_$(CONFIG_WPA_MSG_MIN_PRIORITY)

DRIVER_MAKEOPTS= 

# Full
include $(INCLUDE_DIR)/package.mk

define Package/controlappc-dut/default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=ControlAppC from Wi-Fi Alliance QuickTrack Project
  URL:=http://wi-fi.org/
endef

define Package/controlappc-dut
$(call Package/controlappc-dut/default)
  TITLE+= (WFA)
endef

#define Build/Compile/hostapd-wfa
define Build/Compile
	$(info ************ Build/Compile/controlappc-dut **********)
	$(call Build/RunMake, \
	)
endef

define Build/Prepare
	$(info ************ Build/Prepare **********)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)/
endef

define Build/RunMake
	$(info ************ Build/RunMake $(TARGET_CC) **********)
	CC=$(TARGET_CC) LD=$(TARGET_LD) $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(1) 
		$(2)
endef

define Package/controlappc-dut/install
	$(info ************ Package/controlappc-dut/install $(PKG_BUILD_DIR) **********)
	$(INSTALL_DIR) $(1)/usr/local/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/app $(1)/usr/local/bin/controlappc-dut
endef

#Package/hostapd-wfa/install = $(Package/hostapd-wfa/install)
$(eval $(call BuildPackage,controlappc-dut,))
