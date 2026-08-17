#!/bin/bash
# VPN 配置（你只需要改这里）
VPN_URL="vpn.tongji.cn"
VPN_USER="2351879"
VPN_GROUP=""  # 没有分组就留空：VPN_GROUP=""
VPN_PASSWORD="No200509140544."  # 替换为你的密码

# 自动后台连接 + 保存密码
sudo openconnect \
--protocol array \
-b \
--pid-file=/tmp/vpn.tongji.pid \
-u "$VPN_USER" \
"$VPN_URL" 

