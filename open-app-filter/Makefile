
include $(TOPDIR)/rules.mk

PKG_NAME:=appfilter
PKG_VERSION:=7.0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS +=-Werror=implicit-function-declaration
define Package/appfilter
  SECTION:=Base system
  CATEGORY:=Base system
  DEPENDS:=+libubox +libubus  +libuci +libpthread +libjson-c +libblobmsg-json +libuci-lua +libsqlite3  +libcurl 
  TITLE:=OAF service
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CROSS)gcc" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LIBS="$(TARGET_LDFLAGS) -lm -lpthread -lubox -luci -lubus -ljson-c -lblobmsg_json -lsqlite3 -lcurl" \
	all
endef	


define Build/Compile/Default

endef

define Package/appfilter/description
	OAF service 
endef

define Package/appfilter/conffiles
/etc/fwxd/custom_feature.cfg
/etc/config/fwx
endef


define Package/appfilter/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/fwxd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DATA) ./files/feature.bin $(1)/etc/fwxd/feature.bin
	$(INSTALL_DATA) ./files/custom_feature.cfg $(1)/etc/fwxd/custom_feature.cfg
	$(INSTALL_BIN) ./files/appfilter.init $(1)/etc/init.d/appfilter
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/oafd $(1)/usr/bin
	$(INSTALL_BIN) ./files/rule_manager.lua $(1)/usr/bin/rule_manager
	$(INSTALL_BIN) ./files/hnat.sh $(1)/usr/bin/hnat.sh
	$(INSTALL_DATA) ./files/oaf_version $(1)/etc/oaf_version
	$(INSTALL_DATA) ./files/luci-app-oaf.json $(1)/usr/share/rpcd/acl.d/
endef


$(eval $(call BuildPackage,appfilter))
