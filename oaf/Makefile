
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=oaf
include $(INCLUDE_DIR)/package.mk

PKG_AUTOLOAD:=oaf
RSTRIP:=:

define KernelPackage/oaf
  SUBMENU:=Netfilter Extensions
  TITLE:=OAF netfilter module
  FILES:=$(PKG_BUILD_DIR)/oaf.ko 
  DEPENDS:=+kmod-ipt-conntrack
  KCONFIG:=
endef

define KernelPackage/oaf/description
  oaf netfilter module 
endef

KCFLAGS := -Wno-error=missing-prototypes \
           -Wno-error=missing-declarations \
           -Wno-error=unused-variable \
           -Wno-error=declaration-after-statement \
           -Wno-error=implicit-fallthrough \
           -Wno-error=missing-braces \
           -Wno-error=parentheses \
           -Wno-error=format \
           -Wno-frame-larger-than


MAKE_OPTS:= \
	$(KERNEL_MAKE_FLAGS) \
	M="$(PKG_BUILD_DIR)" \
	KCFLAGS="$(KCFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,oaf))

