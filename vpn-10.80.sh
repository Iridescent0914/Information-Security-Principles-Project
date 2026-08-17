#!/bin/bash
# VPN 配置（你只需要改这里）
VPN_URL="https://10.80.42.150:10012"
VPN_USER="kcsj0018"
VPN_PASS="5hXDwJmxWqVv"
VPN_GROUP=""  # 没有分组就留空：VPN_GROUP=""
CERT="pin-sha256:xS55JRIQehRocNogogcZQg43VVQoeh+y95bj+Z10Cs4="

# 自动后台连接 + 保存密码
echo -e "$VPN_PASS\n" | sudo openconnect \
--servercert "$CERT" \
--protocol anyconnect \
-b \
--pid-file=/tmp/10.80.vpn.pid \
${VPN_GROUP:+--authgroup=$VPN_GROUP} \
-u "$VPN_USER" \
"$VPN_URL" \
--passwd-on-stdin
