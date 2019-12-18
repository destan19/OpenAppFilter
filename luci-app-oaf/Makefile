#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-oaf
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-oaf
	SECTION:=Derry Apps
	CATEGORY:=Derry Apps
	TITLE:=LuCI Support for oaf
	PKGARCH:=all
	DEPENDS:=+kmod-oaf
endef

define Package/luci-app-oaf/description
	LuCI Support for oaf.
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/luci-app-oaf/postinst
#!/bin/sh
if [ -z "$$IPKG_INSTROOT" ]; then
  ( . /etc/uci-defaults/91_luci-app-oaf )
  rm -f /etc/uci-defaults/91_luci-app-oaf

  rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
fi

exit 0
endef

define Package/luci-app-oaf/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./luasrc/* $(1)/usr/lib/lua/luci
	$(INSTALL_DIR) $(1)/
	cp -pR ./root/* $(1)/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	po2lmo ./po/zh-cn/oaf.po $(1)/usr/lib/lua/luci/i18n/oaf.zh-cn.lmo
endef

$(eval $(call BuildPackage,luci-app-oaf))
