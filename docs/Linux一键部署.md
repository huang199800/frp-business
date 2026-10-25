# Linux 一键部署 · 0.2.0

本说明对应公开仓库 [huang199800/frp-business](https://github.com/huang199800/frp-business)。完整的零基础流程与新增节点步骤见[新手快速上手](新手快速上手.md)；客户端步骤见[客户端快速上手](客户端快速上手.md)。

## 环境与域名

控制服务器支持 Debian 12、Ubuntu 22.04/24.04 的 amd64/arm64 systemd 宿主。准备公网 IP，把 `frpc.hhse.top` 和 `frps.hhse.top` 的 A 记录解析到该 IP；有 AAAA 记录时也必须指向可达公网 IPv6。放行 TCP 80/443、TCP 17100–17199 和 TCP/UDP 20100–20199；还需允许服务器访问 GitHub、软件源及证书机构。安装器不会修改云安全组或系统防火墙。

```bash
curl -fL https://raw.githubusercontent.com/huang199800/frp-business/main/install.sh -o /tmp/frp-install.sh && sudo bash /tmp/frp-install.sh --domain frpc.hhse.top --node-domain frps.hhse.top --email hzx0851@gmail.com
```

先下载脚本再执行，保证管理员密码可在交互终端输入。脚本只接受 Debian/Ubuntu 对应版本，检查 DNS 与二进制版本，验证固定 Ed25519 发布公钥签名和 SHA256 后解压。随后安装 PostgreSQL、Caddy、控制服务与本机节点，生成默认套餐并注册 systemd 服务。首次安装会提示设置管理员密码，并只显示一次 TOTP 密钥。务必离线保存 TOTP 和密码。

安装完成后打开 <https://frpc.hhse.top>，用邮箱 `hzx0851@gmail.com`、密码和动态验证码登录。节点 CA 公开下载地址为 `https://frpc.hhse.top/downloads/node-ca.pem`，私钥仅在服务器 root 目录，不给客户。官方 FRP 版本锁定 0.71.1。

## 已安装服务器升级

在**原服务器**运行：

```bash
curl -fL https://raw.githubusercontent.com/huang199800/frp-business/main/install.sh -o /tmp/frp-install.sh && sudo bash /tmp/frp-install.sh --upgrade
```

`--upgrade` 从 `/etc/frp-portal/oneclick.json` 读取原域名、邮箱和端口，不需要手工填写，也不覆盖已有数据库、管理员或节点密钥。升级前创建 root-only 配置与数据库备份；如果备份失败则停止。新程序启动失败会尝试切回旧程序；数据库迁移不自动倒退。`/var/backups/frp-portal/` 保留备份，应按[详细手册](安装与使用手册.md)做恢复演练。

## 新服务器加入为节点

到控制台“套餐与节点”创建一个使用新域名的节点。网页会显示新服务器专用命令和一次性密钥；**只复制命令到新服务器执行，等终端提示再粘贴密钥**。新节点只安装转发程序、证书和服务，不安装 PostgreSQL。它通过 certbot 自动申请/续期公网证书，因此新节点域名先解析到新服务器，TCP 80 必须可达。放行控制端口池 TCP 和业务端口池 TCP/UDP。

节点原机升级：

```bash
curl -fL https://raw.githubusercontent.com/huang199800/frp-business/main/install.sh -o /tmp/frp-install.sh && sudo bash /tmp/frp-install.sh --node-only --upgrade
```

安装身份与证书保留。节点状态文件是 `/etc/frp-portal/node-oneclick.json`，权限 600；不要上传或转发。节点备份保存在 `/var/backups/frp-portal/node-时间戳/`。若证书签发失败，先检查域名 DNS、80 端口和时间同步，然后重试原命令。新增节点后要创建一个绑定它的套餐，客户才会被分配到该节点。

## 检查与维护

```bash
systemctl status frp-portal-serve frp-portal-node caddy
curl --fail https://frpc.hhse.top/healthz
journalctl -u frp-portal-serve -n 80 --no-pager
journalctl -u frp-portal-node -n 80 --no-pager
```

远程节点的公网证书由 certbot timer 维护；默认本机节点的私有 CA 叶证书有效 365 天，需按详细手册在到期前人工重签并监测。控制服务器使用 `/opt/frp-portal/oneclick/releases/` 和 `current` 版本链接；不要直接删旧版本或账目数据库。远程节点使用 `/opt/frp-portal/remote-node/releases/`。需要改变已有安装的域名、邮箱或端口时，安装器会拒绝静默覆盖，请按迁移流程处理。

离线或镜像下载可使用 `--bundle /已验证发布包目录` 或 `--base-url https://可信镜像地址`，发布包仍必须通过安装器内置公钥验签。离线方式仍需要可用的软件包来源。正式收费前还需验收备份恢复、证书续期、服务监测与法律合规要求，不能把“程序已启动”当成全部运营验收。
