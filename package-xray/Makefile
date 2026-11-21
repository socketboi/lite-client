include $(TOPDIR)/rules.mk

PKG_NAME:=lite-client-xray
PKG_VERSION:=$(shell sed -n 's/^XRAY_VERSION=//p' $(CURDIR)/lc-xray)
PKG_RELEASE:=1
PKG_LICENSE:=MPL-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=socketboi

PKG_SOURCE:=Xray-$(PKG_VERSION)-linux-arm64-v8a.zip
PKG_SOURCE_URL_FILE:=Xray-linux-arm64-v8a.zip
PKG_SOURCE_URL:=https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)
PKG_HASH:=64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be

include $(INCLUDE_DIR)/package.mk

define Package/lite-client-xray
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Full Xray JSON service for LiteClient
  URL:=https://github.com/socketboi/lite-client
  DEPENDS:=@aarch64 +ca-bundle
endef

define Package/lite-client-xray/description
 Run trusted Xray JSON files with the full pinned upstream Xray Core.
 This service has its own configuration directory and does not manage firewall rules.
endef

define Package/lite-client-xray/conffiles
/etc/config/lite-client-xray
endef

define Package/lite-client-xray-geodata
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Geodata from the pinned upstream Xray release
  DEPENDS:=+lite-client-xray
  PKGARCH:=all
endef

# The upstream archive contains an already stripped, static Linux executable.
STRIP:=:
RSTRIP:=:
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	unzip -oq $(DL_DIR)/$(PKG_SOURCE) xray LICENSE geoip.dat geosite.dat -d $(PKG_BUILD_DIR)
endef
Build/Compile:=

define Package/lite-client-xray/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/libexec/lite-client-xray
	$(INSTALL_BIN) $(CURDIR)/lc-xray $(1)/usr/bin/lc-xray
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xray $(1)/usr/libexec/lite-client-xray/xray
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/lite-client-xray
	$(INSTALL_BIN) ./files/lite-client-xray.init $(1)/etc/init.d/lite-client-xray
	$(INSTALL_CONF) ./files/lite-client-xray.config $(1)/etc/config/lite-client-xray
	chmod 0700 $(1)/etc/lite-client-xray
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	printf '%s\n' '/etc/lite-client-xray/' > $(1)/lib/upgrade/keep.d/lite-client-xray
	$(INSTALL_DIR) $(1)/usr/share/lite-client-xray
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/lite-client-xray/LICENSE
endef

define Package/lite-client-xray-geodata/install
	$(INSTALL_DIR) $(1)/usr/share/lite-client-xray
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/geoip.dat $(PKG_BUILD_DIR)/geosite.dat $(1)/usr/share/lite-client-xray/
endef

$(eval $(call BuildPackage,lite-client-xray))
$(eval $(call BuildPackage,lite-client-xray-geodata))
