# HTTP API · v0.1.0

基础 URL：配置中的 HTTPS public_url。成功返回 JSON。错误格式统一 `{"error":"可操作的中文原因"}`；400 参数/规则错误、401 凭据失效、403 权限/权益错误、404 无属主记录、429 限流、500 内部错误、503 数据库不可用。未知方法可能由 Go 返回标准405文本，客户端应先检查状态码。

所有写请求为 `Content-Type: application/json`，单请求体上限1MiB，超时10秒。时间为 RFC3339 UTC（可输入带偏移的时间）；接口返回 ISO 时间，页面按本地时区转换。ID 为不可预测字符串，不应通过猜 ID 代替权限验证。

## 鉴权、会话与管理员

- 浏览器使用 HttpOnly、生产 Secure、SameSite=Strict、Path=/ 的 session Cookie，有效12小时。
- CLI/API 可用 `Authorization: Bearer <登录返回的token>`，数据库只存摘要。
- Cookie 写请求必须有与 public_url 一致的 Origin；跨源全部拒绝，不允许宽泛 CORS。非浏览器 API 推荐 Bearer。
- 管理员登录还需 `otp`。管理员写操作另需 `X-Admin-Password` 与 `X-Admin-OTP` 二次验证。
- 节点 token、设备 token 与登录 session 是三个不同作用域，不能混用。
- 服务不信任任意 X-Forwarded-For；同反代来源会共享本机接口限流，因此反代还应配置自己的限流/WAF。当前阈值见源码 http.go；单实例内存限流不是分布式限流。

### 公开和账号接口

| 方法/路径 | JSON 请求 | 返回/行为 |
|---|---|---|
| GET /healthz | 无 | `{status,version}`；查询数据库 |
| POST /api/register | `{email,password}` | 201 `{id}`；邮箱唯一；密码12–72字节；未启用邮箱验证 |
| POST /api/login | `{email,password,otp?}` | `{token,role}` 并设置Cookie；管理员otp必填 |
| POST /api/logout | `{}` | 撤销当前会话并清Cookie |
| POST /api/sessions/revoke | `{}` | 撤销当前用户全部会话（含当前会话） |
| GET /api/me | 无 | `{id,email,role,entitlements:[...],server_now}` |
| POST /api/redeem | `{code,request_id}` | `{id,batch_id,before_at,after_at,repeated}` |
| GET /api/redemptions | 无 | 当前用户最近200条兑换记录，含批次名/前后到期时间 |

示例权益响应：

```json
{
 "id":"USER_ID","email":"user@example.com","role":"user",
 "entitlements":[{"plan_id":"PLAN_ID","name":"基础套餐","max_devices":1,"max_tunnels":3,"tunnel_kibps":1024,"expires_at":"2026-11-22T12:00:00Z","host":"node.example.com","node_name":"上海01","last_seen":"2026-10-23T12:00:00Z","server_now":"2026-10-23T12:00:01Z"}],
 "server_now":"2026-10-23T12:00:01Z"
}
```

兑换 request_id 为8–128字节，推荐 UUID。首次成功后响应丢失，原请求重试返回既有结果。同卡同用户以新的 request_id 重试也返回既有结果；相同 request_id 换另一张卡返回400；同卡其他用户返回400。请求重试不得自动换码，同套餐权益延长不触碰其他账目。

```bash
curl --fail-with-body https://portal.example.com/api/redeem \
 -H 'Authorization: Bearer YOUR_USER_SESSION' -H 'Content-Type: application/json' \
 -d '{"code":"XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX","request_id":"your-unique-uuid"}'
```

### 设备和隧道

| 方法/路径 | JSON 请求 | 返回/行为 |
|---|---|---|
| POST /api/bind-codes | `{name}` | 201 `{code,expires_seconds:300}` |
| POST /api/device/bind | `{code}` | 无用户会话要求；凭一次性码返回201 `{device_id,credential}` |
| GET /api/devices | 无 | 当前用户设备，不返回凭据摘要/明文 |
| POST /api/devices/{id}/revoke | `{}` | 仅本人；返回最大停止窗口；已撤销返回404 |
| GET /api/tunnels | 无 | 当前用户隧道和 node_host |
| POST /api/tunnels | 见下 | 201 Tunnel；remote_port=0自动分配 |
| PATCH /api/tunnels/{id} | `{name,local_host,local_port,paused}` | 仅本人，完整提交这四字段；返回state=saved |
| DELETE /api/tunnels/{id} | 无 | 仅本人，释放端口；返回state=saved |
| GET /api/device/config | 无 | **设备Bearer**，返回`{version:1,host,grant,config_version,state:"saved"}` |

创建隧道：

```json
{"name":"SSH","device_id":"DEVICE_ID","protocol":"tcp","local_host":"127.0.0.1","local_port":22,"remote_port":0}
```

协议只接受tcp/udp。端口必须在节点池内；设备必须是本人、未撤销且属于套餐节点。隧道数量是全账号统计，暂停仍占额度。未激活/过期/封禁/节点维护时拒绝新建和绑定。编辑/删除不会把资源转给其他用户。

`config_version` 是设备配置摘要；`saved` 只表示数据库目标态，**没有伪造 applied 状态**。API返回的grant包含仅该设备的FRP token与授权隧道，属于敏感数据。CLI原子保存配置并重启frpc，日志确认应用；服务端另行强制授权。

### 节点专用接口

| 方法/路径 | 请求 | 响应 |
|---|---|---|
| POST /api/node/lease | 节点Bearer；`{node_id,nonce}`，nonce为32位随机Base32 | `{payload,signature}`，均为Base64；payload为Ed25519签名JSON |
| POST /api/node/check | 节点Bearer；`{node_id,device_id,op,proxy}` | 在线核实权益和隧道，允许返回`{ok:true}`，否则拒绝 |

租约载荷：`version=1,node_id,nonce,issued_at,until,grants[]`。节点核对挑战、签名、公钥、节点身份、最大15秒期限和时钟；payload不得直接由客户端提供。grants中有设备id、独立控制端口、token、套餐到期、单隧道KiB/s及隧道白名单。节点不能请求其他节点的租约。

在线check只允许Login/NewProxy/NewUserConn/NewWorkConn；NewProxy/NewUserConn还要求proxy为该设备当前启用隧道。具体协议、端口与服务端限速仍由节点本地插件验证，双重约束。插件只监听回环，不是公开管理API。

## 管理员接口

管理员 GET 需有效管理员会话；写接口全部需要再次密码/TOTP验证。operator可管理套餐/卡密/普通用户；创建/维护节点仅super。当前没有创建operator或修改角色的公网接口，若需要多人运营应实现有审计的管理员生命周期，不能直接承诺完整人员管理已交付。

| 方法/路径 | 请求/返回 |
|---|---|
| GET /api/admin/overview | `{nodes,plans,batches,users}`；users最多500，batches最多200；不含密码/密钥 |
| GET /api/admin/audit | 最近500条审计；actor/action/target/detail/time |
| POST /api/admin/nodes | `{name,host,control_start,control_end,port_start,port_end}` → 201 `{node_id,credential,verify_key}`，明文凭据一次返回 |
| POST /api/admin/nodes/{id}/state | `{enabled:boolean}`；维护停止授权；仅super |
| POST /api/admin/plans | `{name,node_id,max_devices,max_tunnels,tunnel_kibps,price_cents}` → 201 `{id}` |
| POST /api/admin/cards | 见下 → 201 `{batch_id,codes,warning}`；明文仅本响应返回 |
| POST /api/admin/batches/{id}/disable | `{}`；仅禁用未兑换卡，不删除历史 |
| POST /api/admin/users/{id}/state | `{disabled:boolean}`；仅可变更普通用户，不能禁用自己 |
| POST /api/admin/users/{id}/adjust | `{seconds,reason}` → `{expires_at}`；独立增减流水；原因至少4字节 |

生成卡密：

```json
{"name":"30天卡第一批","note":"运营发卡","plan_id":"PLAN_ID","seconds":2592000,"count":10,"deadline":"2027-01-01T00:00:00Z"}
```

`seconds` 1–315360000，`count`1–1000；非自然月。生成结果本身不代表已销售/收入。生成与一次性导出同一事务审计，响应丢失时到overview核对并禁用对应批次，不能假定未生成。

返回数组只保留最近数量，本版没有分页筛选、CSV流水导出和单卡状态检索API；相关商业运营能力待后续扩展。没有支付接口，不能由前端支付成功发权益。
