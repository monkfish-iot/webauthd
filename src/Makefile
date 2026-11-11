TARGET_D_LIB :=-lz  -luuid -levent  -luci  -lcurl     -lm -ldl  -lsodium    -lnftnl -lmnl   -lnftables -lssl -lcrypto

# UBUS 服务框架, 默认开启; 交叉编译时可用 `make WEBAUTHD_UBUS=0` 关闭
WEBAUTHD_UBUS ?= 1
ifeq ($(WEBAUTHD_UBUS),1)
# OpenWrt 构建会从命令行传入 CFLAGS, 这里必须用 override 才能在其基础上追加
override CFLAGS += -DWEBAUTHD_ENABLE_UBUS=1
TARGET_D_LIB += -lubus -lubox
endif

	
APP_NAME = webauthd


TARGETS = $(APP_NAME) 
LD_LIBRARY_PATH=/usr/lib:$LD_LIBRARY_PATH
SOURCE_COMMON = $(wildcard *.c)  
APP_SRC = $(SOURCE_COMMON) 


#OBJ = $(patsubst %.c, %.o, $(APP_SRC)) 
OBJ = $(patsubst %.c, %.o, $(SOURCE_COMMON))

# 新增的 NFT 模块文件
NFT_MODULES = nft_recovery.c nft_audit.c

 

#CFLAGS  =    -Winline   -Wall -g   
CFLAGS += -DAPP="abcd1234"
CC = gcc  

all: $(TARGETS)  
$(APP_NAME): $(OBJ)
	$(CC)  -g  $(CFLAGS)  $(APP_SRC)  -o $(APP_NAME)  -DAPP="abcd1234"  $(LDFLAGS) $(TARGET_D_LIB)  

 

.PHONY: clean  
clean:  
	rm -rf $(OBJ) $(APP_NAME)

