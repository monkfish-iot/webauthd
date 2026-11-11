#!/bin/sh

# 获取传入的 MAC 地址参数
TARGET_MAC=$1

# 验证 MAC 地址的合法性
validate_mac() {
  local mac=$1
  if echo "$mac" | grep -qE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
    return 0
  else
    return 1
  fi
}

# 如果 MAC 地址不合法，返回空字符串并退出
if ! validate_mac "$TARGET_MAC"; then
  echo ""
  exit 1
fi

# 获取所有无线接口
INTERFACES=$(ubus list | grep hostapd |grep phy | cut -d. -f2)

# 遍历每个接口
for iface in $INTERFACES; do
  # 获取当前接口的客户端列表
  CLIENTS=$(ubus call hostapd.$iface get_clients)

  # 检查目标 MAC 是否在客户端列表中
  if echo "$CLIENTS" | grep -q "$TARGET_MAC"; then
    # 获取当前接口的 SSID
    SSID=$(ubus call hostapd.$iface get_status | jsonfilter -e '$.ssid')
    echo "$SSID $iface"
    exit 0
  fi
done

# 如果没有找到对应的 SSID，返回空字符串
echo ""
exit 0
