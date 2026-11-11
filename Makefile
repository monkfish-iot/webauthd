include $(TOPDIR)/rules.mk

# Name and release number of this package
# 4230 6889
PKG_NAME:=webauthd
PKG_RELEASE:=3
PKG_VERSION:=5.0.0

 
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)


# This specifies the directory where we're going to build the program. 
# The root build directory, $(BUILD_DIR), is by default the build_mipsel
# directory in your OpenWrt SDK directory
#PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)


include $(INCLUDE_DIR)/package.mk

#PKG_CONFIG_DEPENDS:= CONFIG_CONFIGUSE

define Package/webauthd
	SECTION:=Monkfish
	CATEGORY:=Monkfish Softwares
	DEPENDS:= +zlib +libsodium +libuci +libevent2 +libnl +libcurl +libuuid +lua-cjson +libnftnl +libmnl +nftables +kmod-br-netfilter +libopenssl +libubus +libubox
	TITLE:=WebAuthd -- WebAuthd main function
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 

define Build/Compile
        $(MAKE) -C  $(PKG_BUILD_DIR) \
                CC="$(TARGET_CC)" \
                CFLAGS="$(TARGET_CFLAGS)" \
		LD_LIBRARY_PATH="$(STAGING_DIR)/usr/lib:$(LD_LIBRARY_PATH)" \
                LDFLAGS="$(TARGET_LDFLAGS)"\
                ARCH="$(ARCH)"
		###$(TARGET_CROSS)strip $(PKG_BUILD_DIR)/webauthd  
endef

 

define Package/webauthd/description
	WebAuthd program
endef


define	Package/webauthd/install
	$(INSTALL_DIR) $(1)/sbin
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/webauthd   $(1)/sbin/
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) ./files/helpme.sh   $(1)/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/webauthd.init $(1)/etc/init.d/webauthd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/find_essid.sh   $(1)/usr/sbin/
 

	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/webauthd.conf $(1)/etc/config/webauthd
	$(INSTALL_DIR) $(1)/etc
	$(CP) ./files/rednft.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/etc
	$(CP) ./files/brdnft.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/etc
	$(CP) ./files/defnft.conf $(1)/etc/

	$(INSTALL_DIR) $(1)/usr/local/webauthd/
	$(CP) ./files/https $(1)/usr/local/webauthd/
	$(CP) ./files/local_portal $(1)/usr/local/webauthd/
	$(CP) ./files/upload_portal $(1)/usr/local/webauthd/

	$(INSTALL_DIR) $(1)/etc/nginx/conf.d/
	$(CP) ./files/portal.conf $(1)/etc/nginx/conf.d/

	# rpcd 会话 ACL: 登录后的 LuCI 会话才允许调用 webauthd.session.drop_user
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/webauthd.acl.json $(1)/usr/share/rpcd/acl.d/webauthd.json

	 

endef


$(eval $(call BuildPackage,webauthd))
