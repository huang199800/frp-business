# FRP 商业平台 · 第一阶段 0.1.2

## Linux 一键部署

公开仓库：[huang199800/frp-business](https://github.com/huang199800/frp-business)。在已配置公网入口、两个域名DNS和防火墙的Debian12/Ubuntu22.04或24.04服务器执行（替换域名与邮箱）：

```bash
curl -fL https://raw.githubusercontent.com/huang199800/frp-business/main/install.sh -o /tmp/frp-install.sh && sudo bash /tmp/frp-install.sh --domain portal.example.com --node-domain node.example.com --email owner@example.com
```

安装器验证固定公钥签名及SHA256，自动安装PostgreSQL/Caddy、初始化管理员和本机节点、启用HTTPS和systemd服务。首次输入密码并保存TOTP密钥；不在脚本里预置账号密码。详见[Linux一键部署说明](docs/Linux一键部署.md)。实际自动化验收状态以仓库Actions结果为准。

这是实际实现的 TCP/UDP 时长卡闭环交付：Go 控制平台、PostgreSQL、Vue 3 中文用户中心及运营后台、节点租约守护、Windows/Linux CLI Agent。采用官方 **frp 0.71.1** 二进制，无内核补丁。

本阶段适合在隔离测试环境验收和小规模试运营前评估。**还不是需求中全部商业能力均已完成的正式商用版本**。流量账本、全账号总带宽/并发连接限额、邮件找回、域名验证、HTTP/HTTPS、桌面 GUI、在线支付等尚未交付，不应在销售页面承诺这些能力。

## 从这里开始

- [详细安装与使用手册](docs/安装与使用手册.md)：环境要求、源码/压缩包/服务/Docker 部署、日常操作、备份恢复、升级回滚、卸载与排错。
- [版本核实与架构](docs/架构与版本核实.md)：上游源码依据、平台矩阵、数据模型、授权边界与阶段计划。
- [API 文档](docs/API.md)：请求、权限、响应与常见错误。
- [验收结果和已知限制](docs/验收与限制.md)：真实执行结果与未验证项目。
- [第三方声明](third_party/NOTICE.md)：FRP、Go、前端依赖许可证和版本记录。

## 已实现的闭环

1. 初始化数据库与超级管理员，绑定 TOTP 认证器。
2. 创建节点、固定规则套餐、小时/天/周/30/90/365 天或自定义秒数充值卡。
3. 用户注册、兑换、查看套餐到期时间和充值记录。
4. 使用 5 分钟一次性绑定码绑定客户端；创建 TCP/UDP 隧道。
5. 节点校验签名租约，插件强制验证隧道 ID、协议和端口，服务端强制每隧道带宽。
6. 到期、禁用、设备撤销或控制平台中断后，停止新连接并关闭已有转发。
7. 再次兑换同套餐时长卡后恢复；敏感管理操作二次验证并记审计。

## 构建

需要 Go **1.27.3**、Node.js 22.22.0、npm、Git；脚本下载 FRP 需要 Python 3.12+。PostgreSQL 生产建议 17 系列，演示验证版本为 17.6。依赖通过 go.sum 和 package-lock.json 锁定。

```powershell
./scripts/build.ps1
```

```bash
bash scripts/build.sh
```

构建三种目标：Windows amd64、Linux amd64、Linux arm64。构建成功不等于在目标系统完成实机测试。Go 下载直连不可用时可在自己的环境设置可信 GOPROXY；不关闭模块校验。

## 测试

```powershell
$env:FRP_TEST_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/portal_test?sslmode=disable'
go test ./... -count=1 -v
go vet ./...
```

集成测试在指定库里创建唯一临时 schema，结束后删除该 schema。仍建议仅使用专用测试库。真实端到端测试需要**全新空数据库**和空工作目录：

```powershell
python scripts/fetch-frp.py --os windows --arch amd64 --out ../../work/frp
python tests/e2e.py --binary dist/windows-amd64/portal.exe --frp-dir ../../work/frp/frp_0.71.1_windows_amd64 --work-dir ../../work/acceptance --database-url 'postgres://USER:PASSWORD@127.0.0.1:5432/portal_e2e?sslmode=disable'
```

测试的开发 HTTP 模式只允许回环地址。生产必须启用 HTTPS；完整配置见手册。

## 项目结构

```text
cmd/portal/                 CLI、Windows Service 适配、嵌入的前端构建产物
internal/platform/         PostgreSQL 事务、HTTP API、鉴权、签名租约、节点/Agent
  schema.sql               幂等数据库迁移 v1
web/                       Vue 3 + TypeScript 源码与依赖锁
scripts/                   构建、校验下载、安装、预检、卸载
deploy/                    Dockerfile、Compose、Caddy HTTPS 示例
tests/e2e.py               官方 frpc/frps 真实 TCP/UDP 与失效测试
docs/                      中文手册、API、架构和验收
third_party/               上游锁、许可证及依赖许可清单
dist/                      三种构建目标及签名校验文件（交付包内提供）
```

本项目原创源码的商业授权由项目所有者另行决定；此交付没有擅自选择开源许可。第三方代码、二进制和库保留各自许可证，见 third_party。示例品牌“FRP 服务中心”仅为项目自有占位名称。
