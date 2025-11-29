include $(TOPDIR)/rules.mk

PKG_NAME:=simple_packet_sniffer
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Steven Ke <your.email@example.com>
PKG_LICENSE:=MIT

CARGO_PKG_NAME:=simple_packet_sniffer
CARGO_PKG_SOURCE:=src
CARGO_PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cargo.mk

define Package/simple_packet_sniffer
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Simple Packet Sniffer
  DEPENDS:=+libpcap +libstdcpp
  URL:=https://github.com/your-repo/simple_packet_sniffer
endef

define Package/simple_packet_sniffer/description
  A simple packet sniffer that captures packets for 60 seconds and displays their contents.
endef

define Build/Prepare
	$(Build/Prepare/Default)
	$(if $(QUILT),,$(CP) ./src/* $(PKG_BUILD_DIR)/)
endef

define Package/simple_packet_sniffer/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(CARGO_PKG_TARGET_DIR)/release/simple_packet_sniffer $(1)/usr/bin/
endef

$(eval $(call BuildPackage,simple_packet_sniffer))