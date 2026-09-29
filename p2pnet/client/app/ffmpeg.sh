#!/bin/bash
# ffmpeg.sh — P2P 视频通话
#
# 用法: ffmpeg.sh <本机IP> <本机端口> <对方IP> <对方端口> [持续秒数]
# 示例: ffmpeg.sh 192.168.250.2 50001 192.168.250.3 50002 3600
#
# 同时发送和接收视频流，持续指定秒数后自动退出
# 依赖: ffmpeg, ffplay

MY_IP="$1"
MY_PORT="$2"
PEER_IP="$3"
PEER_PORT="$4"
DURATION="${5:-3600}"

if [ -z "$MY_IP" ] || [ -z "$MY_PORT" ] || [ -z "$PEER_IP" ] || [ -z "$PEER_PORT" ]; then
    echo "用法: $0 <本机IP> <本机端口> <对方IP> <对方端口> [持续秒数]"
    echo "示例: $0 192.168.250.2 50001 192.168.250.3 50002 3600"
    exit 1
fi

echo "[*] P2P 视频通话: $MY_IP:$MY_PORT <-> $PEER_IP:$PEER_PORT，持续 $DURATION 秒"

ffplay \
    "udp://:$MY_PORT?listen=1&pkt_size=1316" \
    -fflags nobuffer -flags low_delay \
    -framedrop &

ffmpeg \
    -f avfoundation -i "0:0" \
    -c:v libx264 -preset ultrafast -tune zerolatency \
    -c:a aac -b:a 128k \
    -f mpegts "udp://$PEER_IP:$PEER_PORT@$MY_IP:$MY_PORT?pkt_size=1316" &

sleep "$DURATION"
exit
