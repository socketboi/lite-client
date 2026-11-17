# OpenWrt package recipe for lite-client.
#
# Built with the SDK rather than the bare toolchain, because the SDK is what has the staging tree:
# mbedTLS's headers and a linkable libmbedcrypto both come from there, so none of the MBEDTLS_INC /
# MBEDTLS_LIB arrangement in the top-level Makefile is needed here. Build it with `make package` from
# the top-level Makefile, as docs/BUILD.md describes under "The OpenWrt package". That target links
# this directory into the SDK and runs package/lite-client/clean before compile: Build/Prepare
# copies the tree once, behind a .prepared stamp, so a bare compile after an edit builds the old copy.
#
# Two packages out of one source, from one switch. A household uses one server over one protocol,
# and the QUIC stack that Hysteria2 needs is about as large again as everything else put together
# (docs/BUILD.md, "Sizes"), so making everyone carry both would charge most people for something
# they never open.

include $(TOPDIR)/rules.mk

PKG_NAME:=lite-client
include $(CURDIR)/release.mk
PKG_VERSION:=$(LC_PACKAGE_BASE_VERSION)$(if $(LC_PACKAGE_BUILD),_p$(LC_PACKAGE_BUILD))
PKG_RELEASE:=$(LC_PACKAGE_RELEASE)

PKG_MAINTAINER:=socketboi <336024280+socketboi@users.noreply.github.com>
PKG_LICENSE:=MPL-2.0
PKG_LICENSE_FILES:=LICENSE THIRD_PARTY_NOTICES.md

# The sources are the checkout this file lives in, two directories up. No download, no unpack: the
# package is built from the working tree, which is the only copy there is.
# The VARIANT is part of the path, and leaving it out was not a tidiness matter: OpenWrt builds both
# packages from this one recipe, one after the other, into whatever this names. Without the variant
# both landed in the same directory, so the second build began on top of the first one's objects and
# which plane a package ended up carrying depended on what make thought was out of date. The comment
# under Build/Prepare has always said the tree is copied in "because OpenWrt cleans PKG_BUILD_DIR
# between variants" — it cleans it because the variant is in the name, which it was not.
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/$(BUILD_VARIANT)

# What build this is, worked out HERE rather than inside the copied tree.
#
# The top-level Makefile asks `git describe`, and Build/Prepare copies src, vendor, patches, tools and the
# Makefile into PKG_BUILD_DIR — everything except .git. So git describe ran in a directory that is
# not a checkout, fell back to "unknown", and every packaged binary reported that: the one thing the
# version stamp exists for — saying which build is on a box — was exactly what the package could not
# answer. Asked in $(CURDIR), which is inside the checkout, and handed down as a variable.
LC_GIT_VERSION:=$(shell cd $(CURDIR)/.. && git describe --always --dirty --tags --abbrev=12 2>/dev/null || echo unknown)

include $(INCLUDE_DIR)/package.mk

define Package/lite-client/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=VLESS+REALITY client for small routers
  # +ca-bundle is not a convenience. When a REALITY node does not authenticate us it is serving the
  # site it masquerades as, and the reference then verifies THAT site's certificate against the
  # machine's root store — chain and hostname both — refusing the connection when it does not check
  # out (vendor/Xray-core/transport/internet/reality/reality.go:104-114). A device with no store
  # cannot make that distinction, and src/cert/chain.c refuses rather than waving it through, so
  # without this line the package would install and every masquerade would be dropped.
  #
  # libmbedtls for libmbedcrypto, which the checking computes with; the checking itself is
  # go1.27.1's, in the binary (src/cert/goverify.c), and libmbedx509 is no longer linked.
  # +zlib for src/tls/certcomp.c: the hello offers certificate compression and something has to open
  # what comes back. A base package the system already links, so it costs a NEEDED entry.
  DEPENDS:=+libmbedtls +ca-bundle +zlib +kmod-nft-tproxy +kmod-nft-socket +ip-full
  URL:=https://github.com/socketboi/lite-client
endef

define Package/lite-client
$(call Package/lite-client/Default)
  CONFLICTS:=lite-client-hysteria
  # The pinned APK SDK emits EXTRA_DEPENDS, but not the IPK Conflicts field.
  EXTRA_DEPENDS:=$(if $(CONFIG_USE_APK),!lite-client-hysteria (>=0))
  VARIANT:=reality
  DEFAULT_VARIANT:=1
endef

define Package/lite-client-hysteria
$(call Package/lite-client/Default)
  # Kconfig uses directed dependencies, with the default variant owning the
  # edge. Runtime IPK headers must reject both installation orders instead.
  CONFLICTS:=$(if $(DUMP),,lite-client)
  # APK solver conflicts are native negative dependencies on both variants.
  EXTRA_DEPENDS:=$(if $(CONFIG_USE_APK),!lite-client (>=0))
  TITLE+= (with the Hysteria2 plane)
  VARIANT:=hysteria
endef

define Package/lite-client/description
 A transparent proxy client for OpenWrt devices with 8-16 MB of flash: VLESS over REALITY with
 XTLS-Vision, TPROXY interception, and no dependency on OpenSSL or Go.
endef

Package/lite-client-hysteria/description = $(Package/lite-client/description)

ifeq ($(BUILD_VARIANT),hysteria)
  LC_HYSTERIA:=1
else
  LC_HYSTERIA:=0
endif

# The source tree is copied in rather than built in place: OpenWrt cleans PKG_BUILD_DIR between
# variants, and a build that wrote into the checkout would have the two variants overwriting each
# other's object files.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../src $(CURDIR)/../patches $(CURDIR)/../tools $(CURDIR)/../Makefile $(PKG_BUILD_DIR)/
	# Vendor revisions are verified before packaging; their Git databases are not
	# compiler inputs and must not be duplicated into every variant's build tree.
	rsync -a --exclude='.git' $(CURDIR)/../vendor/ $(PKG_BUILD_DIR)/vendor/
endef

# The SDK's flags are ADDED to ours, never handed over as CFLAGS.
#
# This recipe used to pass CFLAGS="$(TARGET_CFLAGS) -std=c11 -Os -Wall …" — the warning set and the
# base flags copied out of the top-level Makefile, which reads as harmless duplication and is not.
# A variable set on make's command line overrides every `+=` in the makefile, so everything the
# top-level file adds afterwards was discarded: -Isrc, -D_GNU_SOURCE, -I$(MBEDTLS_INC) and
# -DLC_HYSTERIA=1. The package did not build at all — "fatal error: core/args.h: No such file or
# directory" — and the tempting fix, adding -Isrc back here, is worse than the breakage: it compiles,
# it installs, and with -DLC_HYSTERIA gone `#if LC_HYSTERIA` is quietly false, so
# lite-client-hysteria ships without the plane it exists for. lc-tunnel now refuses to compile
# without the switch defined at all, and EXTRA_CFLAGS is how the SDK's own flags get in.
# Asked before anything is built, so that the message names the missing file instead of turning up
# as an install step that could not copy something.
ifeq ($(wildcard $(CURDIR)/files/fingerprint.fpt),)
  $(error files/fingerprint.fpt is missing and the REALITY plane cannot start without it; run `make fingerprint` in the lite-client tree to produce one)
endif

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
		HYSTERIA=$(LC_HYSTERIA) \
		LC_VERSION="$(LC_GIT_VERSION)" \
		BUILD=build-openwrt \
		build-openwrt/lc-tunnel
endef

define Package/lite-client/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build-openwrt/lc-tunnel $(1)/usr/sbin/lc-tunnel
	# The service script is REPLACED on every upgrade, deliberately, and it is the one file here
	# that is not a conffile. Before the UCI options existed the only way to run the Hysteria2 plane
	# was to edit this file by hand on the device, and those edits are overwritten without a word —
	# such a router comes back on the reality plane, refuses to start for want of a public_key, and
	# says so in syslog rather than taking the LAN with it (see the validation in the script). The
	# alternative, making it a conffile, means a fix to the service can never reach the devices that
	# most need it, which is worse: the edits people made are exactly the ones the options replace.
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/lite-client.init $(1)/etc/init.d/lite-client
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/lite-client.config $(1)/etc/config/lite-client
	# The account, the obfuscation password and the node's short id live here, in a directory only
	# root can read. They are never put on the command line: /proc makes a command line readable by
	# every process on the machine, and this one carries the identity the node authenticates.
	$(INSTALL_DIR) $(1)/etc/lite-client
	chmod 0700 $(1)/etc/lite-client
	# THE FINGERPRINT TABLE, WITHOUT WHICH THE REALITY PLANE DOES NOT START AT ALL.
	#
	# lc-tunnel takes it as its first argument on that plane, and the service script refuses to start
	# without it — correctly. What was missing is anything that put it there: no package installed it,
	# no script wrote it, and the string "fingerprint.fpt" appeared in exactly ONE file in the whole
	# repository, the service script that requires it. So the packaged REALITY plane could not start
	# on any router that had not been visited by hand, and the failure arrived at run time, in syslog,
	# after the firewall rules were already up.
	#
	# It is a build input rather than something generated here, because producing it needs Go and
	# uTLS and the SDK has neither. Missing, the build stops — see the check above — since a package
	# that installs a plane it cannot run is worse than one that refuses to be built.
	$(INSTALL_DATA) ./files/fingerprint.fpt $(1)/etc/lite-client/fingerprint.fpt
	# The binary carries mlkem-native and the brotli and zstd decoders (and, in lite-client-hysteria,
	# ngtcp2 and nghttp3), and is in part a translation of Xray, uTLS, Go, hysteria and a piece of
	# Mbed TLS: their notices have to travel with it. Only the licences of what the package ships
	# (--device, which drops zlib and BearSSL): 89 KB with LICENSE, 19 KB after xz.
	$(INSTALL_DIR) $(1)/usr/share/licenses/lite-client
	$(INSTALL_DATA) $(CURDIR)/../LICENSE $(1)/usr/share/licenses/lite-client/LICENSE
	sh $(CURDIR)/../tools/public/notices.sh --device > $(1)/usr/share/licenses/lite-client/THIRD_PARTY_NOTICES.md
endef

Package/lite-client-hysteria/install = $(Package/lite-client/install)

# What package updates and sysupgrade carry across. The SDK generates keep.d entries for
# conffiles absent from the package payload, including owner-created credentials.
#
# These three paths are the DEFAULTS in files/lite-client.config, and they are literals in three
# places: here, in that file, and in the init script's STATE. Pointing uuid_file or auth_file
# somewhere else in the config therefore stops the credential being preserved across a sysupgrade —
# silently, and only noticed on a router that comes back without its account. The init script warns
# about exactly that at startup, since it is the only one of the three that can compare them.
define Package/lite-client/conffiles
/etc/config/lite-client
/etc/lite-client/uuid
/etc/lite-client/auth
/etc/lite-client/obfs
endef

Package/lite-client-hysteria/conffiles = $(Package/lite-client/conffiles)

$(eval $(call BuildPackage,lite-client))
$(eval $(call BuildPackage,lite-client-hysteria))

# The SDK has no REPLACES field; extend its generated IPK control record directly.
# Conflicts plus Replaces lets opkg promote the base variant without forced removal.
ifeq ($(CONFIG_USE_APK),)
define Package/lite-client-hysteria/CONTROL :=
$(Package/lite-client-hysteria/CONTROL)
Replaces: lite-client
endef
endif
