# Kat-Manager

当前版本：**v0.1.1**。

Kat 内核的统一管理脚本。一个入口 `kat.sh`，管理 Kat 支持的 4 种协议：

| 协议 | 服务 | 配置 | 说明 |
|---|---|---|---|
| SS | `kat-ss.service` | `/etc/kat/ss.json` | SS2022（默认 `2022-blake3-aes-128-gcm`）与 SS2017，共 6 种加密方式 |
| AnyTLS | `kat-anytls.service` | `/etc/kat/anytls.json` | 默认用内核的随机证书（客户端跳过校验） |
| Trojan | `kat-trojan.service` | `/etc/kat/trojan.json` | 默认自签 EC 证书；可用自备证书 |
| SOCKS5 | `kat-socks5.service` | `/etc/kat/socks5.json` | 必须有用户名/密码；**不加密，流量明文** |

每个协议一个节点（一个服务），所有服务共用一个内核 `/usr/local/bin/kat`。只支持 Linux amd64 + systemd，需要 root、`python3`、`curl`、`openssl`（Trojan 自签证书）。

**安装就是安装**：只要端口不和别的程序或别的 Kat 协议冲突，就可以装，不影响其他协议，也不管机器上有没有 ss-rust、anytls 等其他服务。本脚本不读、不碰其他服务。

## 一键安装

```bash
# 交互首页（curl | bash 下菜单读 /dev/tty）
curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash

# 非交互一键安装，全部用默认值
curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash -s -- install ss
curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash -s -- install anytls
curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash -s -- install trojan
curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh | bash -s -- install socks5

# 进程替换写法
bash <(curl -fsSL https://raw.githubusercontent.com/shui1iao/Kat-Manager/main/kat.sh) install trojan --port 443

# 也可以 clone 后本地运行
git clone https://github.com/shui1iao/Kat-Manager && cd Kat-Manager && bash kat.sh
```

`kat.sh` 单独运行时（curl | bash、`bash <(curl …)`、只下载了这一个文件），会从仓库 raw 下载 `kat_manager.py`、`kat_config.py`，并核对 `kat.sh` 里内置的 SHA256。下载失败或 hash 不符就直接退出，不做任何改动。下载地址可以用 `KAT_MANAGER_BASE_URL` 覆盖。注意这个变量要给 **bash**，不是给 curl：

```bash
curl -fsSL http://127.0.0.1:18080/kat.sh | KAT_MANAGER_BASE_URL=http://127.0.0.1:18080 bash -s -- install ss
```

本地 checkout（`kat.sh` 旁边有两个 helper）会直接用本地文件。

### 默认值

- 端口：10000–65535 之间随机，避开其他 Kat 协议配置里的端口和本机已占用的 TCP/UDP 端口（读 `/proc/net/{tcp,tcp6,udp,udp6}`）。显式 `--port`（或 `modify --port`）冲突时拒绝，零改动。冲突规则：
  - 任何进程已在监听这个 TCP 端口；
  - SS 还要求这个 UDP 端口空闲（Kat 的 SS 在同一端口收 UDP；AnyTLS/Trojan 的 UDP 走 TCP 内，SOCKS5 的 UDP ASSOCIATE 用临时端口，所以这三个只看 TCP）；
  - 另一个 Kat 协议的配置已经用了这个端口。

  这是唯一的冲突判定。
- 监听 `0.0.0.0`；`--listen IP:PORT` 可以指定（IPv6 写 `[::]:PORT`）。
- 凭据：
  - SS：`2022-blake3-aes-128-gcm` 加随机 16 字节 Base64 密钥（SS2017 用 20 位随机密码）。
  - AnyTLS：16 位随机密码（规则与 AnyTLS-Manager 相同）。
  - Trojan：20 位随机密码。
  - SOCKS5：用户名 `kat` 加 7 位随机字符，密码 20 位随机。
- 内核：GitHub Release 最新版，按 `.sha256` 校验。已经装了受管内核就直接复用，不再下载。
- 节点地址：查询 `https://ipv4.icanhazip.com`；查不到就输出 `<服务器IP>` 占位。`--host` 只影响输出。

## 首页

`bash kat.sh`（或 curl | bash 不带参数）进入首页。配色与 SS-Rust-Manager 一致：青色边框和标题、绿色的仓库/作者和编号、蓝色的分组标题。每次操作结束后提示「按回车继续...」，然后清屏回到首页。

```
============================================
          Kat 管理脚本 v0.1.1
============================================
仓库: github.com/shui1iao/Kat-Manager
作者: shui1iao
============================================
内核版本：0.7.0
SS     ：运行中  端口 21177
AnyTLS ：未安装
Trojan ：未安装
SOCKS5 ：未安装

=== 协议 ===
1. 安装协议
2. 管理协议（查看 / 修改 / 启停 / 卸载）

=== 内核 ===
3. 更新内核
0. 退出脚本
============================================
请输入选项 [0-3]:
```

- 协议状态：
  - **运行中**（绿）、**已停止**（红），后面跟端口；上次运行失败（failed）也算已停止，并注明。
  - **未安装**（黄，与 SS-Rust-Manager 一样用 `\033[0;35m`）。
  - **已存在（非本脚本安装）**（红，附原因）：`kat-<协议>.service` 是手写的（没有 `# KatManager*` 标记）、在 `/usr/lib` 或 `/lib` 下，或者只有 `/etc/kat/<协议>.json` 没有单元。本脚本不接管、不覆盖，安装和管理都拒绝。
  - **异常**（红，附原因）：本脚本的格式但无法可靠判定，例如标记重复/与配置或证书不符、单元 hash 与内核不符、有 drop-in、systemd 处于 activating 等过渡状态或无法查询。不会当成未安装。
- 内核版本：`X.Y.Z`；`未安装`（红）；`X.Y.Z（非本脚本安装）`（红，`/usr/local/bin/kat` 存在但没有 `/var/lib/kat-manager/kernel.json`，本脚本不覆盖也不复用）。
- 只有标准输出是终端时才有颜色；管道、重定向或设置了 `NO_COLOR` 时没有任何 ANSI 码。curl | bash 时标准输出仍是终端，照常有颜色。
- 没有交互终端时只打印状态总览，然后退出（非 0）。

「1. 安装协议」：选协议 → 端口（回车随机）→ SS 选加密方式 → SOCKS5 填用户名 → 密码（回车随机）→ Trojan 可填自备证书路径 → 安装并输出节点信息。该协议已经由本脚本安装时提示「已安装，可在管理协议里修改」，不会覆盖。

「2. 管理协议」：选协议后进入子菜单：1 查看配置、2 修改配置（端口 / SOCKS5 用户名 / 密码，回车不变，密码输入 `r` 随机生成）、3 启动、4 停止、5 重启、6 查看状态、7 卸载（先确认，再询问是否删除配置文件，回车保留）、8 查看日志、0 返回。原 1–7 含义不变。

「3. 更新内核」：输入目标版本，回车取 latest。

## 命令一览

```
bash kat.sh                               交互首页
bash kat.sh <动作> <协议> [参数]           协议：ss | anytls | trojan | socks5（也可写成 <协议> <动作>）
bash kat.sh status                        状态总览（与首页的状态部分相同）
bash kat.sh update [--version X.Y.Z | --binary FILE --sha256 HEX]
bash kat.sh help
```

| 动作 | 说明 |
|---|---|
| `install <协议>` | 安装并启动，输出节点信息。端口冲突或该协议已安装时拒绝，零改动 |
| `view <协议>`（`config`） | 输出节点信息（Surge / Mihomo / URI） |
| `status <协议>` | `systemctl status` |
| `logs <协议> [--lines N] [--follow]` | 受管单位 journal；默认最近100行、非实时、无分页；实时仅显式选择 |
| `modify <协议>` | `--port` / `--listen` / `--credential-file`；SS 可加 `--method`（换方式时必须同时给新凭据）；SOCKS5 可加 `--username`。运行中的服务会重启；停止的服务保持停止 |
| `start` / `stop` / `restart <协议>` | 启停 |
| `uninstall <协议> [--purge]` | 停止并禁用。交互时询问是否删除配置/证书/单元（默认保留）；`--purge` 不问直接删；非交互且没给 `--purge` 时保留 |
| `update` | 更新共享内核（作用于所有 Kat 服务），失败自动退回 |

常用参数：

```
--version X.Y.Z              内核版本（install/update；默认 latest）
--binary FILE --sha256 HEX   离线内核（install/update）
--port N | --listen IP:PORT
--method M                   SS：2022-blake3-aes-128-gcm | 2022-blake3-aes-256-gcm | 2022-blake3-chacha20-poly1305
                                 aes-128-gcm | aes-256-gcm | chacha20-ietf-poly1305
--credential-file F          密码/密钥从文件读，取文件的精确内容（末尾不要有换行，例如用 printf '%s' 写入）
--username NAME              SOCKS5 用户名
--cert F --key F [--sni D]   Trojan 自备证书
--cert F --key F --tls-policy legacy-insecure --ack-certificate-change   AnyTLS 自备证书（与 AnyTLS-Manager 相同）
--host ADDR                  节点输出用的地址
--purge                      uninstall 时直接删除
```

示例：

```bash
bash kat.sh install ss --port 21177 --method aes-128-gcm --credential-file /root/ss.pw
bash kat.sh install socks5 --username alice --credential-file /root/socks.pw
bash kat.sh install trojan --cert /root/fullchain.pem --key /root/privkey.pem
bash kat.sh modify trojan --port 8443
bash kat.sh uninstall socks5 --purge
bash kat.sh update --version 0.6.2
```

## 查看日志与手改 0.7 配置

本脚本保持基础生命周期，不提供规则/配置编辑器、统计/连接/策略组代理或 TLS/ACME 向导。首页仍为 1 安装、2 管理、3 更新；管理子菜单仅增加 **8 查看日志**。

```bash
bash kat.sh logs ss                 # 最近100行，非实时，--no-pager
bash kat.sh logs anytls --lines 50
bash kat.sh ss logs --follow        # 显式实时跟随，Ctrl-C 停止查看
```

菜单 8 回车看最近100行，输入 `f` 才跟随。日志仍可用于受管服务已停止/failed、配置 JSON 无效时排障，不要求配置检查成功或管理 socket 可达；foreign、drop-in、伪 marker、受管路径 symlink/hash 冲突仍拒绝。只查询所选固定 `kat-<协议>.service`，不读取其他服务日志。

**日志可能包含目标、来源、动态名称等私密信息，分享前自行检查；不承诺脱敏。** 这里只查看 systemd journal。用户若自行配置 `log.file`，文件日志须按自己的路径查看，不由脚本扫描或接管。

Kat ≥ 0.7 时，用户可自行编辑 JSON 的高级区；基础 view/status/start/update/modify 会核对单入站/协议/单身份/监听/凭据和真实 `kat check`，复杂 schema、规则/组/provider 跨引用由内核校验。不复制另一套 0.7 规则解析器，不自动改 API 或其他配置区。旧内核继续使用原严格读取边界。

`modify` 仍只改所选端口/凭据等基本字段，保留未选高级区的 JSON 值、凭据和证书引用（格式化空白可能变化）。**运行服务按原版重启；停止服务只保存不启动**，不新增自动 reload 事务。若自己手改后需要热重载，直接用原生内核命令：

```bash
kat check /etc/kat/ss.json
kat reload -c /etc/kat/ss.json
```

原安装的随机、自签、legacy-insecure、supplied 默认和 marker 不变。手改复杂 TLS（多证书/文件跟随/ACME 等）后，若旧 marker 不能可靠表达客户端验证/SNI，查看节点会提示「该TLS配置需自行按配置设置客户端」，不生成猜测的 Surge/Mihomo/URI、不推定已签发、不自动降为 insecure。start/update 仍以有效内核配置为准，不因旧单文件展示假设拒绝。配置、单位、内核所有权/hash 校验没有放宽，也不写新 TLS marker。

本版本未修改 Kat 内核，也未验证真实 ACME/DNS 写入或签发；内核的 6h 未覆盖、AnyTLS 已建 carrier 可继续新开逻辑流、api/stats.file 重载非原子三项已知限制原样保留。内核二进制 update、失败恢复及旧 migrate/adopt/rollback 命令退役决定均不变。

## 节点输出

每个协议都输出 Surge、Mihomo、URI 三种格式，节点名都是 `VPS`。下面的凭据都是占位。

**SS（SS2022）**

```
Surge:
VPS = ss, 203.0.113.10, 21177, encrypt-method=2022-blake3-aes-128-gcm, password=AAECAwQFBgcICQoLDA0ODw==, udp-relay=true
Mihomo:
  - {"name":"VPS","type":"ss","server":"203.0.113.10","port":21177,"cipher":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==","udp":true}
URI:
ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@203.0.113.10:21177#VPS
```

SS2017 的 URI 用 SIP002 的 Base64URL 形式 `ss://BASE64URL(method:password)@host:port#VPS`。

**AnyTLS**（随机证书，客户端跳过校验）

```
Surge:
VPS = anytls, 203.0.113.10, 53588, password="Example-pw@1234", skip-cert-verify=true, udp-relay=true
Mihomo:
  - {"name":"VPS","server":"203.0.113.10","port":53588,"password":"Example-pw@1234","skip-cert-verify":true,"type":"anytls","udp":true}
URI:
anytls://Example-pw%401234@203.0.113.10:53588?security=tls&type=tcp&allowInsecure=1&insecure=1#VPS
```

**Trojan（自签证书）**

```
Surge:
VPS = trojan, 203.0.113.10, 40443, password="ExampleTrojanPw12345", skip-cert-verify=true, udp-relay=true
Mihomo:
  - {"name":"VPS","type":"trojan","server":"203.0.113.10","port":40443,"password":"ExampleTrojanPw12345","skip-cert-verify":true,"udp":true}
URI:
trojan://ExampleTrojanPw12345@203.0.113.10:40443?security=tls&type=tcp&allowInsecure=1&insecure=1#VPS
```

**Trojan（自备证书）**：客户端校验证书，不跳过校验，带 `sni`。

```
Surge:
VPS = trojan, 203.0.113.10, 443, password="ExampleTrojanPw12345", sni=node.example.com, udp-relay=true
Mihomo:
  - {"name":"VPS","type":"trojan","server":"203.0.113.10","port":443,"password":"ExampleTrojanPw12345","sni":"node.example.com","udp":true}
URI:
trojan://ExampleTrojanPw12345@203.0.113.10:443?security=tls&type=tcp&sni=node.example.com#VPS
```

**SOCKS5**

```
SOCKS5 不加密，流量明文……
Surge:
VPS = socks5, 203.0.113.10, 41080, katuser1, ExampleSocksPw123456, udp-relay=true
Mihomo:
  - {"name":"VPS","type":"socks5","server":"203.0.113.10","port":41080,"username":"katuser1","password":"ExampleSocksPw123456","udp":true}
URI:
socks5://katuser1:ExampleSocksPw123456@203.0.113.10:41080#VPS
```

在终端里，分隔线是青色，地址/端口/用户名/密码/加密的值和 Surge/Mihomo/URI 三行是绿色。颜色只包在整行或整个值的外面：去掉 ANSI 码后与上面的文本逐字一致，复制时不会带进多余字符。

特殊字符的处理规则：

- **Surge**：值里出现字母数字和 `+/=._-` 以外的字符时，用双引号括起来，并把 `"` 和 `\` 写成 `\"`、`\\`（Surge 文档 “Quoted Values”，iOS 5.21.0+ / Mac 6.8.0+）。SOCKS5 的用户名或密码需要加引号时，改用 `username="…", password="…"` 命名参数。
- **Mihomo**：单行 JSON 流式映射，本身就是合法 YAML。
- **URI**：用户信息部分按 RFC 3986 百分号编码（包括 `/ @ : # %` 和空格）。
- IPv6 地址在 Surge 行和 URI 里写成 `[addr]`。

## Trojan 证书

- **默认自签**：安装时用 openssl 生成 P-256 EC 自签证书（`CN=kat-manager`，有效期 10 年）。
  - 文件：`/etc/kat/trojan/cert.pem`（0644）、`/etc/kat/trojan/key.pem`（0600），目录 0700。
  - 客户端跳过证书校验。
  - 单元标记：`# KatManagerTLS=self-signed`。
- **自备证书 `--cert/--key`**：
  - 先检查：证书和私钥配对、证书在有效期内。然后复制到 `/etc/kat/trojan/`（只复制，不移动原文件）。
  - 证书由 CA 签发（颁发者与主体不同）时：
    - 标记为 `# KatManagerTLS=supplied`，加一行 `# KatManagerSNI=<域名>`，客户端校验证书。
    - SNI 取 `--sni`；没给就取证书 SAN 里的第一个 DNS 名（非通配），没有 SAN 时取 CN。
    - SNI 必须被证书覆盖，否则拒绝。
  - `--cert` 本身就是自签证书时，按自签模式处理（客户端跳过校验，不接受 `--sni`）。
- 标记结构保持严格：TLS/SNI 标记缺失、重复、取值未知均拒绝。旧内核仍严格核对来源；0.7 手改有效复杂 TLS 时，只放弃无法可靠推定的客户端输出，不改 marker，也不弱化单位/hash/路径所有权。
- `modify` 不更换证书。基础安装仍使用上面的证书选项；0.7 高级 TLS 由用户自己改 JSON、check/reload 并设置客户端。

AnyTLS 保持 AnyTLS-Manager 的行为：默认用随机证书（配置里不写 `tls`，标记 `random-insecure`）；自备证书需要 `--cert --key --tls-policy legacy-insecure --ack-certificate-change`（标记 `legacy-insecure`）。

## 内核更新

- `update`（菜单「3. 更新内核」）：
  1. 下载 `kat-<版本>-linux-amd64` 和对应的 `.sha256`，校验文件名和 hash，确认 `kat version` 报告的版本正确。
  2. 用新内核对所有现存 Kat 配置（四个协议）执行 `kat check`，全部通过才继续。
  3. 当前内核临时硬链接到 `/usr/local/bin/.kat.old-<pid>`，新内核在同一目录原子 rename 成 `/usr/local/bin/kat`。
  4. 刷新所有单元的 `KatManagerSHA256` 标记，重启原本在运行的服务（停止的不启动）。
  5. 任何一步失败（服务起不来、写单元/记录失败、`daemon-reload` 失败），自动把内核、单元和内核记录按字节退回更新前，并让原来在运行的服务重新运行。
  6. 成功后删除旧内核，**不保留回滚件**；`kernel.json` 只记录 `{version, sha256, source}`。上一版留下的 `/usr/local/bin/kat.rollback` 会在这次成功更新后顺手删除，其他时候忽略。

  下载/校验/check 失败都是零改动（不留临时文件）。
- 已经是最新版本时提示「已是最新版本（X.Y.Z）」，不做任何改动；`--version` 等于当前版本时同样不改动。
- 想换回旧版本，就用 `update --version <旧版本>`，流程与升级完全相同。
- 机器上有不是本脚本安装的 `kat-*` 单元时，更新会被拒绝（换内核会影响它们，本脚本又不管理它们）。

## 卸载

- `uninstall <协议>`：停止并禁用服务，然后询问是否删除配置、证书和单元（默认保留）。
- `--purge`：不询问，直接删除。
- 非交互且没给 `--purge`：保留。
- 只处理 Kat 自己的文件，不碰、也不会去启用其他服务（例如 ss-rust）。
- 还有其他 Kat 服务（任何协议的配置或单元仍在）时保留内核。最后一个协议删除文件时，删除 `/usr/local/bin/kat`、`/var/lib/kat-manager/kernel.json`（以及上一版遗留的 `kat.rollback`），和空的 `/etc/kat`、`/var/lib/kat-manager`。

## 失败时的安全顺序

所有改动类命令（install、modify、start/stop/restart、uninstall、update）都按同一个顺序执行，并共用 `/run/lock/kat-manager.lock`：

1. **先做完所有可能失败的预检和准备，再动任何服务**：参数和配置的严格读取、端口检查、下载和 hash 校验、`kat check`、目录权限检查、卸载用的暂存目录。这一步失败时零改动。
2. 记录相关服务原来的 enabled/active 状态。
3. 停止/禁用服务后如果再失败，会把文件放回原处，把服务恢复成原来的状态，并在错误信息里如实说明恢复结果。
   - install：失败时删除本次写入的文件（以及本次新装的内核），其他服务不受影响。
   - modify：新配置起不来时写回原配置并重启；原来没在运行的服务不会被启动。
   - uninstall：文件从暂存目录放回，服务恢复原状态。
   - update：见上一节。

`/var/lib/kat-manager` 自身权限过宽（root 所有的真实目录）时收紧为 0700 并提示一行。`/etc/kat` 和证书目录不会自动改：权限不是 0700 时，会在任何改动之前拒绝，并提示人工 `chmod 700`。

## 文件与格式

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/kat` | 共享内核 |
| `/etc/kat/<协议>.json`（0600，目录 0700） | 配置 |
| `/etc/kat/anytls/`、`/etc/kat/trojan/` | 证书（0700 目录，cert 0644，key 0600） |
| `/etc/systemd/system/kat-<协议>.service` | 单元；开头是 `# KatManager*` 注释标记 |
| `/var/lib/kat-manager/kernel.json` | 内核记录 `{version, sha256, source}` |
| `/run/lock/kat-manager.lock` | 所有改动类操作共用的 flock 锁 |

单元标记和 `kernel.json` 与 SS-Rust-Manager / AnyTLS-Manager 开发版 Kat 模式写出的兼容：那一版装的 `kat-ss`、`kat-anytls` 直接当作普通的已安装协议显示和管理，不需要重装。那一版留下的其他文件——`/var/lib/kat-manager/migrations/`、`/var/lib/kat-manager/backups/`、`kernel.json` 里的 `rollback` 字段、单元里的 `KatManagerAdopted` 标记、`/usr/local/bin/kat.rollback`——本脚本不读也不报错；前两个目录原样保留（可以手工删除），`kat.rollback` 在下次成功更新内核后删除。

环境变量（测试或自建镜像用）：`KAT_MANAGER_BASE_URL`（helper 下载地址）、`KAT_RELEASE_BASE_URL`（Release 下载前缀，下面是 `v<版本>/kat-<版本>-linux-amd64[.sha256]`）、`KAT_RELEASE_LATEST_URL`（返回 `{"tag_name":"vX.Y.Z"}` 的地址）、`KAT_PUBLIC_IP_URL`、`KAT_MANAGER_SETTLE_SECONDS`（启动后等待判定 active 的秒数）。

## 版本与验证

本次精简改动已通过基础格式/配置/生命周期兼容回归 **42 项**、日志入口与手改 0.7 配置的定向回归 **7 项**，使用隔离目录、systemctl/journalctl 测试替身及真实内核的 check/version；没有操作运行中的服务或读取真实 journal。最终版本只追加版本/header、Bash/Python 语法、helper pin，以及独立 curl wrapper 和 hash 篡改拒绝短验证，不重复长测。

测试不等于真实 journal/实时流、ACME/DNS 签发续期、第三方客户端全矩阵或长期运行验证。下面的客户端格式说明沿用原版本验证结论，本次未重新跑完整互通矩阵。

维护者修改 helper 后必须同步更新 wrapper 的 SHA256：

```bash
bash scripts/pin-helpers.sh
bash scripts/pin-helpers.sh --check
```

## 已知限制

- 只支持 linux-amd64、systemd、root。不做 VLESS、Snell、ACME 配置/证书模式向导、自动定时更新；有效 0.7 手改配置只作最低兼容。
- 每个协议只管一个节点、一个用户。不提供迁移旧服务、接管手工安装、内核回滚：手写的 `kat-<协议>` 显示为「已存在（非本脚本安装）」，需要人工处理（例如停掉并删除后再用本脚本安装）。
- 换内核版本只能用 `update --version X.Y.Z` 重新下载，不保留旧二进制。
- `--credential-file` 取文件的精确内容，末尾有换行会被拒绝（控制字符不合法）。
- AnyTLS 用随机证书需要内核 0.6.1 及以上。
- Surge 行只做了字段级测试（Surge 不能在 Linux 运行）；Mihomo 行和 URI 用真实 mihomo 做了连通测试。mihomo 的分享链接解析器不对 `socks5://` 的用户信息做百分号解码，所以 SOCKS5 凭据含特殊字符时，请用 Mihomo 行，不要用 URI 导入 mihomo（URI 本身符合 RFC 3986）。
- AnyTLS URI 现在把密码里的 `/` 编码为 `%2F`。旧脚本不编码，那种写法会被标准 URI 解析器截断。
- AnyTLS 的 Mihomo 行比旧 AnyTLS-Manager 格式多了末尾的 `"udp":true`（其余字段和顺序不变）。旧格式没有这个字段，mihomo 会把节点当成只支持 TCP，UDP 改走客户端本机直连、不经节点（mihomo v1.19.32 实测：UDP 出口是客户端自己的 IP）。四个协议的 Mihomo 行现在都带 `"udp":true`，并在互通测试里验证了 UDP 确实经过 Kat 服务端。
- helper 从 `main` 分支下载：main 上的 helper 改了但 `kat.sh` 没有重新 pin 时，curl|bash 会拒绝运行（安全失败）。发布时 helper 和 `kat.sh` 要放在同一个提交里。
- SOCKS5 不加密，只适合在可信网络里用，或者作为其他加密隧道的上游。
