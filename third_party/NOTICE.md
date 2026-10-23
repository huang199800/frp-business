# 第三方软件、来源与分发声明

本交付没有修改或嵌入 fatedier/frp 核心源码；通过独立官方二进制与公开 HTTP 插件协议集成。控制平台和前端代码为本次原创实现，不复制 frp-panel 或商业平台实现。根项目的商业授权由项目所有者决定，第三方权利不因此改变。

## FRP

- 项目：https://github.com/fatedier/frp
- 固定版本：v0.71.1；Release 2026-10-14；源码 tag 的提交短 SHA 72d643d。
- 许可证：Apache License 2.0，原文在 `frp-LICENSE`，保留作者版权。固定 tag 源码未发现独立 NOTICE。
- 上游包 URL 和 SHA256：`frp-lock.json`。
- 未修改的对应源码压缩包：`sources/frp-v0.71.1-source.tar.gz`，来自官方 GitHub tag API。
- 本项目未承诺官方关联或背书；FRP、Go 等名称属各自权利人。

Apache-2.0 允许商业使用和分发，但要保留许可证、适用声明；对上游文件的修改需标注。本交付没有上游内核修改。若今后修改，应保留版权与变更说明，重新审查依赖和分发条件。

## FRP 的 MPL-2.0 依赖

`github.com/fatedier/yamux v0.2.0` 使用 **MPL-2.0**，不能因为 FRP 主项目 Apache-2.0 就忽略其条件。本交付保留 MPL 原文与版权，并附上该固定版本未修改的完整模块源码：

- `sources/yamux-v0.2.0.zip`，Go 模块源存档（包含其许可证）。
- 官方来源：https://github.com/fatedier/yamux/tree/v0.2.0
- 具体源校验和及许可证路径在 `dependency-inventory.json`。

接收 FRP 二进制的用户可从本交付获取该 MPL Covered Software 的对应源代码，按 MPL 权利使用。商业组合并不自动要求本项目原创服务全部采用 MPL，但如修改 MPL 覆盖的文件，相关文件源代码及声明需按该许可证提供。当前没有修改 yamux。

## Go 和前端依赖

`dependency-inventory.json` 保存 192 条模块/包版本记录（含构建/测试依赖的保守超集），附 Go h1 校验或 npm integrity、归属和许可证路径；`licenses/` 保存 202 份实际读取到的 LICENSE/NOTICE 等文件。Go 直接依赖包括：

| 依赖 | 锁定版本 | 许可 |
|---|---|---|
| github.com/jackc/pgx/v5 | v5.9.2 | MIT |
| golang.org/x/crypto | v0.56.0 | BSD 系列 |
| golang.org/x/sys | v0.47.0 | BSD 系列 |
| Vue | 3.5.44 | MIT |
| Vite / plugin-vue | 8.3.5 / 6.0.10 | MIT |
| TypeScript | 5.9.3 | Apache-2.0 |
| vue-tsc | 3.3.13 | MIT |

实际构建依赖以 go.mod/go.sum、web/package-lock.json 为准。FRP 依赖模块清单来源固定 tag 下 `go mod download -json all`，覆盖开发/测试超集，不等于精确运行时 SBOM；官方 frps 二进制的 Go build info 也已检查。前端依赖清单记录本机实际安装的运行时/构建依赖；其他平台未安装的可选原生构建包不随本源码交付的 node_modules 分发，重打包时仍需重新收集对应平台许可。

许可检测先根据实际文本分类，再检查未识别项；这是技术分发记录，**不是法律意见或对未来所有组合的合规保证**。新增依赖、上游升级、内核补丁或另行封装二进制时，运营方应重做审查。Docker 基础镜像另有系统包许可与安全更新义务，当前未生成/审核完整镜像 SBOM，Docker 正式发布前需要补齐。

前端构建工具的 lightningcss / 对应原生包也是 MPL-2.0，相关声明已保存在清单及许可证目录；它们仅在构建阶段使用，最终浏览器产物和运行镜像不包含这些构建工具的二进制。源码包排除 node_modules；如另行分发构建环境或工具包，应补齐其对应源码和许可义务。

PostgreSQL、Caddy、Node、Go、Python 等由运行环境/构建镜像提供，各自按官方许可分发。交付包不包含 PostgreSQL 数据库程序或测试数据库，不包含运营私钥、账号、节点凭据或卡密明文。
