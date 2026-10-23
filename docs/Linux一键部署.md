# Linux 一键部署 · 0.1.3

适用于**专用或已评估兼容的 Debian 12、Ubuntu 22.04/24.04 systemd 服务器**，amd64/arm64。脚本安装发行版PostgreSQL及Caddy（Caddy统一使用官方稳定源）、启动控制平台和本机节点、初始化管理员和默认套餐。数据库/业务范围仍是第一阶段，详见[验收与限制](验收与限制.md)。

## 准备

1. 具有sudo/root权限的Linux公网服务器。控制域名如portal.example.com、节点域名如node.example.com均解析到该服务器公网IP。
2. 放行TCP80/443、TCP17100–17199（设备控制），以及TCP/UDP20100–20199（业务）。安装器不会修改系统防火墙或云安全组。
3. 服务器可访问GitHub、系统软件源、证书机构；仅有CGNAT内网地址不能自动获得公网入口。
4. 检查现有Caddy站点、8080端口、PostgreSQL集群；建议用全新专用服务器首次部署。已有同名frp_portal数据库/角色但没有本安装器状态时拒绝接管。

## 一条命令

替换三个参数为你自己的域名和管理员邮箱，然后在Linux服务器执行：

```bash
curl -fL https://raw.githubusercontent.com/huang199800/frp-business/main/install.sh -o /tmp/frp-install.sh && sudo bash /tmp/frp-install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com
```

先下载到文件再执行，避免管道占用交互输入。建议先阅读脚本；正式部署可把main替换为核实过的完整提交SHA，锁定入口脚本，或下载后对照独立发布的SHA256。下载下来的安装器会使用**内置Ed25519公钥**先验证发布清单，再校验选定架构包SHA256，验证后才解压并运行程序。不会把从相同下载站随意取得的新公钥当信任根，也不使用curl -k。

安装包可从仓库GitHub Release（发布后）或固定releases/v0.1.3目录取得。默认下载地址写在install.sh中；若GitHubraw大文件受限，可用 `--base-url https://github.com/huang199800/frp-business/releases/download/v0.1.3`（实际发布后）。替代下载地址仍受同一内置公钥校验，不能替换为未签名包。

首次要求输入并确认管理员密码，明文不写进命令参数/脚本。随后输出一次TOTP密钥和otpauth链接，请立即录入认证器并离线保存。完成后打开HTTPS控制台，用邮箱、密码、动态码登录，进入充值码管理发卡。默认套餐1台设备、3条隧道、每隧道1024KiB/s，参考价格0；请按产品规则创建正式套餐，不把默认价格当在线收款。

节点TLS使用独立私有CA签发的证书，客户端必须下载并信任 `https://控制域名/downloads/node-ca.pem`，然后按[完整手册](安装与使用手册.md)配置agent.json的ca_file。**这份CA不是私钥**；CA私钥只在服务器root私有目录，不能下发给用户。控制台HTTPS由Caddy自动申请/续期；节点证书有效365天，目前需人工按维护窗口续签，不是自动续期产品。

## 安装位置与重复执行

- `/etc/frp-portal/serve/control.json`、`node/node.json`：root持有、服务账号只读。
- `/etc/frp-portal/oneclick.json`：root-only安装状态（含生成的数据库密码），不要公开上传。
- `/etc/frp-portal/pki/`：root-only CA私钥和签发材料。
- `/opt/frp-portal/oneclick/releases/`：按版本保存二进制和许可证，current指向当前版本。
- `/var/lib/frp-portal/serve`、`node`：服务状态；`public/node-ca.pem`仅公开CA证书。
- `/var/log/frp-portal/`：结构化轮转日志。
- `frp-portal-serve.service`、`frp-portal-node.service`：开机启动、异常重启、最小权限账号。
- `/var/backups/frp-portal/时间戳/`：升级前数据库逻辑备份和配置副本，root-only。

相同参数重复执行不会覆盖原有控制签名种子、管理员或数据库密码。域名/邮箱/端口变化拒绝静默覆盖，应按迁移流程操作。升级前备份失败则停止；新程序失败会尝试切回旧二进制，数据库不自动倒退。首次安装失败保留状态，修正网络、DNS、证书或权限后用相同参数重试；若管理员已创建但后续尚未完成，可能要求重新输入管理员密码和当前TOTP。

本版不是任意旧版本数据库的万能升级器。当前schema_version=1；未来不兼容迁移必须有单独策略。配置业务历史、卡密和权益账目不可通过删除数据库“重装”来处理。

```bash
systemctl status frp-portal-serve frp-portal-node caddy
curl --fail https://portal.example.com/healthz
journalctl -u frp-portal-serve -n 100 --no-pager
tail -n 100 /var/log/frp-portal/node.log
```

完整数据库备份/旧备份防重兑对账见原手册。仅卸载应用服务可运行 `sudo bash scripts/uninstall-linux.sh node` 和serve；不会删除数据库、CA、日志。Caddy新增站点位于 `/etc/caddy/frp-portal.d/portal.caddy`；其他已有站点不被脚本重写，修改主文件前保存备份。

## 常用选项

```bash
# 控制私有8080被占用时改端口；重复部署必须继续使用相同参数。
sudo bash install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com --control-port 18080
# 只部署控制平台，节点按完整手册独立配置。
sudo bash install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com --without-node
# 只做部署预检，不配置应用（下载和验证发布包仍会产生临时文件）。
sudo bash install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com --check
```

离线可提前下载install.sh、两个架构包中的适用包、SHA256SUMS与.sig到同一目录，使用 `--bundle /该目录`。**系统依赖软件包仍需已有缓存/离线软件源**，不能宣称无任何依赖的完全离线安装。

`--local-test`与`--admin-password-file`只用于隔离CI测试，不用于公网正式部署；内部CA不等于公开可信证书。密码文件须root持有且权限600，测试后应通过自己的测试环境销毁流程清理。

## 安全和验证边界

公开代码库不代表整个商业产品已正式验收。本版仍无流量配额计费、账号总带宽、HTTP/HTTPS虚拟主机、桌面GUI或在线支付。PostgreSQL使用系统源；Caddy统一按[Caddy官方说明](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)启用稳定仓库，并固定校验仓库签名密钥。原生安装器使用这些软件源中的版本，发布前需核对发行版维护周期；不盲目锁定已过安全维护的操作系统包。

自动化安装的状态取决于真实LinuxCI/服务器结果；本机Windows语法与单元测试不等于Linux部署成功。GitHub Actions会执行Linux构建、数据库及原生FRP端到端测试、隔离localhost的一键安装和重复执行检查；以仓库实际工作流结果为准。
