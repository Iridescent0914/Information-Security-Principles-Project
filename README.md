# 信息安全原理课程设计：轻量级 UDP 安全隧道

本项目实现了一个基于 UDP 的轻量级三层 VPN（安全隧道）。客户端将 TUN 虚拟网卡收到的 IPv4 报文加密、封装为自定义 UDP 报文发往服务端；服务端解密后注入本地 TUN，并通过 Linux IPv4 转发与 NAT 访问公网。项目覆盖协议设计、密钥协商、加密传输、重放防护、TUN 收发、路由/NAT 部署和抓包验证。

> 仅用于课程实验与受控网络环境，不应视为生产级 VPN 实现。

## 项目完成情况

核心功能、网络转发与安全验证均已完成，并保留了可复核的日志与 pcap 证据。

| 验收项 | 结果 |
| --- | --- |
| 6 报文 UDP 完整握手 | 已验证 |
| ECDH、HKDF、Finished 双向校验 | 已验证 |
| AES-128-GCM 加密隧道与 TUN 双向收发 | 已验证 |
| 重放、密文篡改、认证标签篡改拒绝 | 已验证 |
| 错误 ClientFinished 拒绝建立会话 | 已验证 |
| 程序生成报文与 pcap UDP Payload 逐字节一致 | 已验证 |
| 经服务端 NAT 的 `ping`、`curl -4`、`wget -4`、`apt update` | 已验证 |

最终自动检查位于 [`secure_tunnel_final/evidence/logs/07_final_check.txt`](secure_tunnel_final/evidence/logs/07_final_check.txt)。

## 架构与数据路径

实验使用老师提供的 OpenConnect 网络作为底层承载（underlay），在其上搭建本项目的安全隧道（overlay）：

```text
Kali Client                         VMware Ubuntu Server
───────────                         ────────────────────
应用流量                                  UDP :2026
    │                                        │
 tjvpn0 (10.8.0.2) ←── AES-GCM UDP ──→ tjvpn0 (10.8.0.1)
    │                                        │
 client.py                              server.py
                                             │
                                  IPv4 forwarding + NAT
                                             │
                                          Internet
```

- `tun0`：老师 OpenConnect 创建的课程 VPN 接口，提供 UDP 外层通信，必须保留。
- `tjvpn0`：本项目创建的 TUN 接口，承载解密后的内层 IPv4 报文。
- 服务端监听 UDP `2026`；服务端 OpenConnect 地址 `<SERVER_VPN_IP>` 可能随重连改变，不能在代码或部署命令中写死。
- 切换客户端默认路由前，必须先为 `<SERVER_VPN_IP>/32` 保留经原物理接口的路由，防止外层 UDP 被再次送入隧道而形成递归。

## 安全协议设计

### 外层固定头

所有自定义报文均采用网络字节序，共 9 字节固定头：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 B | 固定为 ASCII `TJ` |
| Packet Type | 1 B | `0x01` 握手、`0x02` 数据、`0x03` 关闭 |
| Sequence Number | 4 B | 数据报文序列号 |
| Payload Length | 2 B | Payload 长度 |

实现会严格校验 Magic、类型、长度和序列号范围。握手报文的序列号固定为 `0`；数据报文序列号严格递增，拒绝重复或旧报文。

### 握手与会话建立

握手严格包含 6 个 UDP 报文：

```text
ClientHello → ServerHello → ClientKeyExchange → ServerKeyExchange
            → ClientFinished → ServerFinished
```

- 使用 `secp256r1` 执行 ECDH，生成共享 Pre-Master Secret。
- ClientHello / ServerHello 各携带 16 B Random；ServerHello 传递服务端证书。
- 客户端将收到的证书转换为 DER 后，与本地 `certs/server_cert.pem` 的 DER 进行精确比对，实现证书固定（pinning）。
- `Pre-Master || Client Random || Server Random || Transcript Hash` 作为 HKDF-SHA256 输入，派生 16 B 会话密钥；HKDF `info` 为 `TJVPN-2026-session-key`。
- Finished 使用会话密钥对四条前置握手消息的 Transcript Hash 计算 HMAC-SHA256；双向验证成功才进入 `ESTABLISHED`。

### 数据通道

- 算法：AES-128-GCM。
- 每包随机生成 12 B IV；Payload 为 `IV || Ciphertext || 16 B Auth Tag`。
- 仅在 GCM 认证成功后才更新接收序列号并写入 TUN，因此可同时拒绝篡改包与重放包。
- 关闭时使用 `TYPE_CLOSE`、序列号 `0`、负载 `close` 进行简单双向确认。

## 代码结构

```text
secure_tunnel_final/
├── client.py                 # 客户端：握手、加/解密、TUN 与 UDP 转发
├── server.py                 # 服务端：握手、加/解密、TUN 与 UDP 转发
├── protocol.py               # TJ 固定头与报文类型定义
├── handshake.py              # 六类握手消息的编解码
├── crypto_utils.py           # ECDH、Transcript、HKDF、Finished
├── session.py                # AES-GCM 数据包与重放/认证异常处理
├── tun_utils.py              # Linux TUN 创建
├── certs/server_cert.pem     # 客户端固定的服务端证书
├── tests/                    # 单元测试、分阶段与安全异常测试
├── evidence/                 # pcap、日志与最终检查结果
└── tools/                    # pcap 握手检查和 UDP Payload 提取工具
```

根目录中的 `阶段任务-详细版.md`、`连接步骤.md` 和 `文档记录/` 是完整的实施、部署、验收记录；`项目分析.md` 解释了设计背景和拓扑选择。

## 运行条件

- Linux（代码通过 `/dev/net/tun` 与 `fcntl.ioctl` 创建 TUN，不支持直接在 Windows 运行）。
- Python 3 与 `cryptography==3.4.8`。
- root/sudo 权限，以及 `iproute2`、`iptables`、`tcpdump` 等网络工具。
- 客户端与服务端已具备 UDP `2026` 的底层可达性。

安装依赖：

```bash
cd secure_tunnel_final
python3 -m pip install -r requirements.txt
```

## 基本运行流程

以下仅给出程序启动顺序。完整的路由、NAT、抓包、回滚与清理命令请以 [`连接步骤.md`](连接步骤.md) 和 [`文档记录/阶段六-实施总结.md`](文档记录/阶段六-实施总结.md) 为准。

1. 在服务端确认课程 VPN 已连接，并读取其当前外层地址：

   ```bash
   ip -4 -br addr show tun0
   ```

2. 在服务端启动隧道：

   ```bash
   cd secure_tunnel_final
   sudo python3 -u server.py
   ```

   握手完成后，另开终端配置服务端 TUN：

   ```bash
   sudo ip addr add 10.8.0.1/24 dev tjvpn0
   sudo ip link set tjvpn0 up
   sudo ip link set tjvpn0 mtu 1300
   ```

3. 在客户端启动隧道，其中 `<SERVER_VPN_IP>` 为上一步读取的地址：

   ```bash
   cd secure_tunnel_final
   sudo python3 -u client.py <SERVER_VPN_IP>
   ```

   握手完成后，另开终端配置客户端 TUN：

   ```bash
   sudo ip addr add 10.8.0.2/24 dev tjvpn0
   sudo ip link set tjvpn0 up
   sudo ip link set tjvpn0 mtu 1300
   ```

4. 先验证内层连通：

   ```bash
   ping -c 4 10.8.0.1
   ```

5. 如需让客户端通过服务端访问公网，按阶段六记录配置服务端 IPv4 forwarding、FORWARD 规则和 MASQUERADE；在客户端保留 `<SERVER_VPN_IP>/32` 的原路径后，再将默认路由切换至 `tjvpn0`。

按 `Ctrl+C` 时，客户端发送 CLOSE；停止后应按实施记录清理 TUN、路由、NAT 与 FORWARD 规则，避免影响原网络。

## 测试与证据

单元测试位于 `secure_tunnel_final/tests/unit/`，覆盖协议头、HKDF、ECDH、Finished、AES-GCM 与 TUN 创建。安全异常测试位于 `tests/security/`。

已保存的证据包括：

- `evidence/pcap/07_handshake.pcap`：正常握手抓包（6 包）。
- `evidence/pcap/07_ping_cipher.pcap`：加密 DATA 报文抓包。
- `evidence/logs/07_program_packet_detail.txt`：程序生成的 Header、IV、明文、密文、Tag 与完整 TJ 报文。
- `evidence/logs/07_pcap_packet.txt`：从 pcap 提取的 UDP Payload。
- `evidence/logs/07_final_check.txt`：最终安全验收结论。

## 设计边界

该实现刻意保持为课程设计所需的单客户端、单会话原型：没有多客户端并发管理、握手重传/超时恢复、乱序窗口、密钥轮换、独立方向密钥、AAD 绑定、证书链验证或生产级防 DoS 机制。它可以清楚展示安全隧道的关键机制，但若用于真实网络，应使用经过审计的 WireGuard、OpenVPN 或 IPsec 等方案。

## 相关文档

- [`项目分析.md`](项目分析.md)：项目目标、拓扑和技术分析。
- [`阶段任务-详细版.md`](阶段任务-详细版.md)：七阶段实施方案。
- [`连接步骤.md`](连接步骤.md)：实验环境接入与操作说明。
- [`文档记录/`](文档记录/)：各阶段实施、测试和验收记录。
