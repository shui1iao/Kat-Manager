# 更新日志

## 0.1.0（2026-10-25）

首个版本。从 SS-Rust-Manager / AnyTLS-Manager 开发版 Kat 模式抽出，作为独立的统一管理脚本。

- 入口 `kat.sh`（bash）+ `kat_manager.py` / `kat_config.py`（Python helper）。curl|bash 时下载 helper，并按内置 SHA256 校验。
- 协议：SS（6 种加密方式，SS2022 默认）、AnyTLS、Trojan、SOCKS5，各自一个服务 `kat-<协议>.service`，共用 `/usr/local/bin/kat`。每个协议一个节点。
- 安装就是安装：唯一的冲突判定是端口（任何进程在监听的 TCP 端口；SS 另看 UDP；另一个 Kat 协议的配置）。不读、不碰 ss-rust、anytls 等其他服务，它们在不在都不影响安装。
- 交互首页，配色和布局与 SS-Rust-Manager 一致：
  - 青色边框和标题，绿色的仓库/作者和编号，蓝色分组（=== 协议 === / === 内核 ===）。
  - 显示内核版本和四个协议的状态：运行中（绿）/ 已停止（红）+ 端口、未安装（黄）、已存在（非本脚本安装）/ 异常（红，附原因）。
  - 菜单：1 安装协议、2 管理协议（查看 / 修改 / 启停 / 状态 / 卸载）、3 更新内核、0 退出；每次操作后「按回车继续...」再回到首页。
  - 只在标准输出是终端时输出颜色，`NO_COLOR` 或管道/重定向时不输出 ANSI。
  - 通过 /dev/tty 交互，curl|bash 下可用。
- 节点输出：每个协议都有 Surge / Mihomo / URI 三种格式。终端里分隔线青色、值和三行格式绿色，去掉颜色后文本逐字不变。
  - SS 新增 Mihomo 行。
  - AnyTLS URI 改为把 `/` 编码为 `%2F`。
  - AnyTLS 的 Mihomo 行末尾加上 `"udp":true`：旧 AnyTLS-Manager 格式没有它，mihomo 会让 UDP 走客户端直连而不经节点。
- Trojan：
  - 默认 EC 自签证书，客户端跳过校验。
  - 可用 `--cert/--key [--sni]` 自备证书，客户端校验并带 SNI。
  - 单元标记 `KatManagerTLS=self-signed|supplied`、`KatManagerSNI`，规则严格。
- SOCKS5：强制用户名和密码（缺省随机生成），输出明文警告，拒绝无认证。
- 内核：
  - latest 或 `--version`，`.sha256` 校验，只支持 linux-amd64。
  - `update`：对所有 Kat 配置执行 check → 原子替换 → 刷新标记 → 重启正在运行的服务；任何一步失败自动退回到更新前的内核。成功后不保留旧二进制（不再有回滚件），已是最新版本时不做任何改动。
  - 改动类操作共用 `/run/lock/kat-manager.lock`。
- 卸载：按协议单独卸载。交互询问时默认保留，`--purge` 直接删除。其他 Kat 服务还在时保留内核，最后一个删除时删内核和记录。只处理 Kat 自己的文件。
- 不提供迁移、迁移回滚、接管手工安装、内核回滚。手写的 `kat-<协议>` 显示为「已存在（非本脚本安装）」，安装和管理都拒绝，不覆盖。
- 兼容开发版 Kat 模式装的 `kat-ss` / `kat-anytls`（单元标记、`kernel.json`），当作普通已安装协议管理；它留下的 `migrations/`、`backups/`、`rollback` 字段不读也不报错，`kat.rollback` 在下次成功更新后删除。
- 失败安全：所有改动类命令先完成全部预检和准备（读取校验、端口、下载、`kat check`、目录权限、暂存目录），然后才停止或禁用服务。停服后如果失败，会恢复文件和服务原来的 enabled/active 状态，并如实报告。
- 严格读取器覆盖四个协议的管理格式和内核 0.6.x 的静态规则；Trojan 密码不超过 4096 字节，SOCKS5 用户名/密码 1–255 字节。
