#!/bin/bash
# wghelp.sh — 用打好的洞配置原生 WireGuard
# 
# 用法: wghelp.sh <我的私钥> <我的mesh IP> <对方公钥> <对方mesh IP> <对方公网地址:端口>
#
# 示例:
#   ./wghelp.sh YGzbJJ8... 192.168.250.2 BDDBwN2... 192.168.250.3 5.6.7.8:51820
#
# 注意: 需要 root 权限（wg set / ip link 操作）
#       需要 wireguard-tools 安装（wg 命令）
#       需要 WireGuard 接口已存在（会自动创建 wghelp0 如果不存在）
#
# 支持系统: Linux (macOS 需用 wg-quick)

set -e

MY_PRIVKEY="$1"
MY_IP="$2"
PEER_PUBKEY="$3"
PEER_IP="$4"
PEER_ENDPOINT="$5"
IFACE="${6:-wghelp0}"
KEEPALIVE=25

if [ -z "$MY_PRIVKEY" ] || [ -z "$MY_IP" ] || [ -z "$PEER_PUBKEY" ] || [ -z "$PEER_IP" ] || [ -z "$PEER_ENDPOINT" ]; then
    echo "用法: $0 <我的私钥> <我的mesh IP> <对方公钥> <对方mesh IP> <对方公网地址:端口> [接口名]"
    echo "示例: $0 YGzbJJ8... 192.168.250.2 BDDBwN2... 192.168.250.3 5.6.7.8:51820"
    exit 1
fi

# 检查 root
if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 需要 root 权限"
    echo "运行: sudo $0 $MY_PRIVKEY $MY_IP $PEER_PUBKEY $PEER_IP $PEER_ENDPOINT"
    exit 1
fi

# 检查 wireguard-tools
if ! command -v wg &>/dev/null; then
    echo "错误: wireguard-tools 未安装 (wg 命令不存在)"
    exit 1
fi

# 创建接口（如果不存在）
if ! ip link show "$IFACE" &>/dev/null; then
    echo "[*] 创建 WireGuard 接口: $IFACE"
    ip link add dev "$IFACE" type wireguard
fi

# 从私钥推导公钥
MY_PUBKEY=$(echo "$MY_PRIVKEY" | wg pubkey 2>/dev/null)
if [ -z "$MY_PUBKEY" ]; then
    echo "错误: 无效的私钥，无法推导公钥"
    exit 1
fi

# 配置接口（如果还没配）
CURRENT_KEY=$(wg show "$IFACE" private-key 2>/dev/null | awk '{print $NF}')
if [ "$CURRENT_KEY" != "$MY_PRIVKEY" ]; then
    echo "[*] 配置本端私钥和 IP..."
    wg set "$IFACE" private-key <(echo "$MY_PRIVKEY")
    ip addr add "$MY_IP/24" dev "$IFACE" 2>/dev/null || true
fi

# 添加或更新 peer
echo "[*] 添加 Peer: $PEER_PUBKEY"
echo "[*] Endpoint: $PEER_ENDPOINT"
echo "[*] AllowedIPs: $PEER_IP/32"

# 先移除旧配置（如果有）
wg set "$IFACE" peer "$PEER_PUBKEY" remove 2>/dev/null || true

# 添加 peer
wg set "$IFACE" peer "$PEER_PUBKEY" \
    endpoint "$PEER_ENDPOINT" \
    persistent-keepalive $KEEPALIVE \
    allowed-ips "$PEER_IP/32"

# 确保接口 up
ip link set "$IFACE" up

echo ""
echo "[✓] WireGuard 配置完成!"
echo "    本端: $MY_IP (公钥: ${MY_PUBKEY:0:16}...)"
echo "    对端: $PEER_IP @ $PEER_ENDPOINT"
echo "    接口: $IFACE"
echo ""
echo "    测试连通性:"
echo "      ping $PEER_IP"
echo ""
echo "    查看状态:"
echo "      wg show $IFACE"
echo ""
echo "    持续保活（NAT 映射维持）:"
echo "      watch -n 20 'wg show $IFACE'"
echo ""
echo "    清理（移除 peer）:"
echo "      sudo wg set $IFACE peer $PEER_PUBKEY remove"
