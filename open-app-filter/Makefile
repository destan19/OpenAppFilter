
include $(TOPDIR)/rules.mk

PKG_NAME:=appfilter
PKG_VERSION:=6.1.6
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS +=-Werror=implicit-function-declaration
define Package/appfilter
  SECTION:=TT Apps
  CATEGORY:=TT Apps
  DEPENDS:=+libubox +libubus +libuci +libpthread +libjson-c +libblobmsg-json
  TITLE:=OAF client and config service
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CROSS)gcc" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LIBS="$(TARGET_LDFLAGS) -lm -lpthread -lubox -luci -lubus -ljson-c -lblobmsg_json" \
	all
endef	


define Build/Compile/Default

endef

define Package/appfilter/description
  openappfilter app
endef

define Package/appfilter/conffiles
/etc/config/appfilter
/etc/config/user_info
endef

define Package/appfilter/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/appfilter
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/*.cfg $(1)/etc/appfilter/ 
	$(INSTALL_BIN) ./files/appfilter.init $(1)/etc/init.d/appfilter
	$(INSTALL_BIN) ./files/oaf_rule $(1)/usr/bin
	$(INSTALL_BIN) ./files/gen_class.sh $(1)/usr/bin
	$(INSTALL_DATA) ./files/appfilter.config $(1)/etc/config/appfilter
	$(INSTALL_DATA) ./files/user_info.config $(1)/etc/config/user_info
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/oafd $(1)/usr/bin
	$(INSTALL_BIN) ./files/hnat.sh $(1)/usr/bin
endef


$(eval $(call BuildPackage,appfilter))

