# mail.com 邮箱接码 API

将自有 `mail.com` 账号密码导入为持久化的单 URL 接码接口，并支持同步或显式创建账号别名。

## 数据流

1. 管理员导入 `邮箱----密码`，也可使用 `邮箱----密码----http://代理用户:代理密码@主机:端口`。
2. 服务加密保存密码和代理凭据，生成不可猜测的 `/code/<access_key>`。
3. 同一账号的登录、OAuth、收信、别名和取码请求始终复用其绑定代理，不自动轮换或切换到其他代理。
4. 调用接码 URL 时，服务复用 `sid` 和 2 小时 access token 查询收件箱。
5. 服务按收件地址、时间和可选发件人筛选，读取正文并提取 4 至 8 位验证码。
6. 地址永久保存到 SQLite，并同步生成 `data/邮箱----接码API.txt`。

密码、代理凭据、`sid`、access token 均使用 Fernet 加密后写入数据库；日志不记录 URL、邮箱、密码、代理密码或 token。

## 本地启动

Linux/macOS 可使用仓库内的单文件管理脚本启动、关闭或重启服务：

```bash
chmod +x service.sh
./service.sh start
./service.sh status
./service.sh restart
./service.sh stop
```

服务默认监听所有网卡的 `8988` 端口，使用 `.venv/bin/python`（不存在时使用 `python3`），自动读取项目根目录下的 `.env`，PID 保存在 `.run/server.pid`，标准输出和错误输出统一写入 `logs/server.log`。持续查看日志可运行 `./service.sh logs`。API 响应和网页中生成的取码地址会自动使用当前请求的协议、服务器地址和端口；经过反向代理时支持 `X-Forwarded-Proto` 和 `X-Forwarded-Host`。

Windows PowerShell 也可以直接启动：

```powershell
cd D:\grokfree\mail-com-code-api
& D:\grokfree\.venv\Scripts\python.exe server.py `
  --bind 0.0.0.0 `
  --port 8988 `
  --public-base http://127.0.0.1:8988 `
  --data-dir .\data
```

首次启动会生成：

- `data/admin.token`：管理 API Bearer token
- `data/master.key`：本地加密密钥
- `data/mail-code.db`：账号、别名、会话和 URL
- `data/邮箱----接码API.txt`：可直接导入下游的地址文件

这四类文件都必须备份，且不能提交到仓库。丢失 `master.key` 后无法解密已保存账号。

## 导入账号

文本导入支持 `----`、`---`、Tab、逗号分隔。推荐 `----`：

```powershell
$body = @'
first@mail.com----password-1
second@mail.com----password-2----http://proxy-user:proxy-pass@proxy.example:8080
'@
$token = Get-Content .\data\admin.token -Raw
Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8988/admin/import?verify=true&sync_aliases=true' `
  -Headers @{Authorization = "Bearer $($token.Trim())"} `
  -ContentType 'text/plain; charset=utf-8' `
  -Body $body
```

`verify=false` 只保存，不立即登录。`verify=true` 会检测账号密码和当前服务器网络；同时传 `sync_aliases=true` 会读取该账号已有别名并为每个别名生成独立 URL。

JSON 导入也可使用：

```json
{"accounts":[{"email":"first@mail.com","password":"password-1"}]}
```

代理也可以使用供应商常见的 `host:port:user:pass` 格式；服务会转换为 HTTP 代理 URL 后加密保存。代理绑定是一次性的：同一账号再次导入不同代理会返回 `proxy_binding_exists`，不会静默替换。当前不支持 SOCKS，且不会自动轮换或循环分配代理。

也可以在服务器私有文件中配置固定代理池：

```dotenv
MAIL_API_PROXY_POOL_FILE=/etc/mail-com-code-api-proxies.txt
```

文件每行一个 HTTP 代理，权限应设为 `0600`。新账号没有显式代理时会领取下一条未使用代理并加密写入数据库；同一代理不会自动分给第二个账号，池耗尽返回 `proxy_pool_exhausted`。重启后根据数据库中的既有绑定继续分配，不会更换已绑定账号的代理。前端和账号列表接口只显示是否已绑定，不显示代理 IP、主机、端口或认证信息。
也可以在网页里的“代理池”面板直接追加代理，保存后会写入服务器上的 `proxy-pool.txt`。

## 接码

导出文件每行固定为：

```text
first@mail.com----https://mail-code.example.com/code/<access_key>
```

直接请求：

```bash
curl 'https://mail-code.example.com/code/<access_key>'
```

默认只接受最近 10 分钟邮件。常用参数：

- `wait=60`：最多长轮询 60 秒。
- `since=2026-08-17T01:20:00Z`：只接受该时间后的邮件。
- `max_age=1800`：最大邮件年龄；`0` 表示不限制。
- `sender=openai.com`：只接受发件人包含该文本的邮件。

有验证码：

```json
{"email":"first@mail.com","code":"123456","mail":{"id":"...","date":"...","sender":"...","subject":"..."}}
```

没有新邮件或未识别到唯一验证码时返回 HTTP 200：

```json
{"email":"first@mail.com","code":null,"mail":null}
```

## 导入与验证

`POST /admin/import` 使用 `Authorization: Bearer <admin.token>` 导入邮箱密码；首次导入响应中的 `lines` 只应保存到调用方。之后用正确邮箱密码调用 `/auth/login`，服务才返回该邮箱的接码地址。错误密码不会返回地址。网页控制台同样需要先输入 `data/admin.token` 完成管理员验证，令牌保存在当前浏览器的 `localStorage` 中，之后打开页面会自动验证。

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `/admin/import` | 管理员批量导入并永久保存账号 |
| `POST` | `/auth/login` | 用邮箱密码验证并返回该邮箱 API 地址 |
| `POST` | `/query` | 携带邮箱密码查询该账号验证码 |
| `POST` | `/aliases/split` | 携带邮箱密码一次创建 1-9 个别名并返回独立 API，可选指定或随机分裂域名；会自动按账号总地址上限 10 裁剪 |

以下管理接口仍要求 `Authorization: Bearer <admin.token>`，不会被公开页面调用：

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/admin/accounts?page=1&page_size=20` | SQL 分页查看母号、密码、状态和该母号的全部子号 |
| `GET` | `/admin/addresses?page=1&page_size=20` | SQL 分页查看母号/子号及取码 URL，不返回密码 |
| `GET` | `/admin/export` | 下载 `邮箱----接码API` |
| `POST` | `/admin/check` | 登录与 token 连通性诊断 |
| `POST` | `/admin/query` | 按邮箱批量匹配并查询验证码 |
| `POST` | `/admin/aliases/sync` | 同步账号已有别名并生成 URL |
| `POST` | `/admin/aliases` | 显式创建一个或多个 mail.com 别名并生成 URL |
| `POST` | `/admin/aliases/split` | 网页控制台分裂别名（管理员验证） |

检查账号：

```json
{"account":"first@mail.com","sync_aliases":true}
```

创建别名（会修改 mail.com 账号设置）：

```json
{"account":"first@mail.com","address":"new-alias@mail.com"}
```

批量创建别名：

```json
{"account":"first@mail.com","addresses":["a@engineer.com","b@engineer.com"]}
```

批量查询验证码：

```json
{"emails":["first@mail.com","second@mail.com"],"max_age":600}
```

一键分裂请求：

```json
{"email":"first@mail.com","password":"password-1","count":3,"domain":"engineer.com"}
```

`domain` 可选；不传时默认沿用账号邮箱域名。子号名称默认随机组合常见英文名、姓氏、排列方式和数字，不包含母号前缀或固定的 `split` 标记，更接近真人邮箱格式。传入 `engineer.com` 时只固定域名部分，子号名称仍然随机生成。
如果同时传 `domain` 和随机域名参数，优先使用手动指定的 `domain`。
mail.com 当前按账号总地址数限制，上限约为 10 个；因为原始邮箱本身也占 1 个，所以通常最多还能新建 9 个别名。

随机从 mail.com 域名池中选择 `.com` 或 `.net` 域名：

```json
{"email":"first@mail.com","password":"password-1","count":9,"random_domain_tlds":["com","net"]}
```

也兼容布尔参数：

```json
{"email":"first@mail.com","password":"password-1","count":9,"random_com":true,"random_net":true}
```

## IP 与限流判断

HAR 没有显示 token 绑定 IP 的字段；同一 `sid` 可按 scope 换不同 access token。mail.com 明确存在登录频率和网络信誉控制，表现可能是 `429`、`403`、无 `ott` 重定向或 `sid` 交换失败。`POST /admin/check` 会把结果保存为：

- `ready`：登录/刷新及邮件 scope token 正常。
- `bad_credentials`：账号密码错误或登录失败重定向。
- `rate_limited`：当前服务器出口触发频率限制。
- `blocked`：当前服务器网络被拒绝。
- `session_expired`：缓存会话失效，服务会自动完整重登一次。

单一出口只能确认“该服务器 IP 当前可用”，不能证明 token 在不同 IP 间可迁移。要确认硬性 IP 绑定，需要用同一短期 token 从第二个受控出口做只读查询对照；不要把 token 交给公共代理。

## Docker 部署

```bash
cp .env.example .env
# 修改 .env 中的 PUBLIC_BASE、ADMIN_TOKEN 和 MASTER_KEY
docker compose up -d --build
curl http://127.0.0.1:8988/health
```

容器端口映射到服务器的 `8988`。可以直接通过 `http://服务器IP:8988` 访问，生产环境也可使用 Caddy/Nginx 或 Cloudflare Tunnel 提供 HTTPS。

## 验证

```powershell
& D:\grokfree\.venv\Scripts\python.exe -m unittest discover -s tests -v
& D:\grokfree\.venv\Scripts\python.exe -m py_compile server.py storage.py mailcom_client.py code_extract.py
```
