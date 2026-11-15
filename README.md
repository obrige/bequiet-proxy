# bequiet-proxy

把 [bequiet](https://bequiet.pages.dev) 这个取回服务，变成一个**真正可用的 HTTP 代理和 SOCKS5 代理**——
可以给整台机器用，也可以只给一个程序用。

单文件实现，**只依赖 Python 标准库**，不需要 `pip install`，不需要任何第三方包。

| 目标地址 | 上游实际请求 |
|---|---|
| `https://duckduckgo.com` | `https://bequiet.pages.dev/fonts/https://duckduckgo.com` |
| `wss://echo.websocket.org` | `wss://bequiet.pages.dev/fonts/wss://echo.websocket.org` |

## 为什么需要 MITM

上游服务把目标 URL 放在路径里（`/fonts/<目标URL>`），而代理拿到的是一个**已经建立的 TLS 会话**，
没法把这种 URL 形式套进去。所以本工具在本地终结 TLS：

1. 自建一个根 CA，**每台设备各自生成**（不写死、不分发）；
2. 对每个被拦截的域名，用 CA 现场签发一张叶子证书；
3. 解密客户端请求，再以 `/fonts/<目标URL>` 的形式重新发往上游。

`
   客户端  --CONNECT/GET-->  bequiet-proxy  --HTTPS-->  bequiet.pages.dev/fonts/<目标>
   （信任本机 CA）   （MITM 解密）        （与源站建立真实 TLS）
`

## 快速开始

### 直接跑 Python

需要 Python 3.8 或更高版本（Windows 上装好 Python 后自带 `certutil`，可直接管理信任库）。

`
:: 启动代理
python bequiet_proxy.py --http-port 9090 --socks-port 1080

:: 或者双击 start.cmd
`

### 用 Docker

`
:: 构建并启动
docker compose up -d

:: 把 CA 装进本机信任库（读的是 ./ca，与容器共用同一份证书）
python bequiet_proxy.py --install-ca --ca-dir ./ca
`

详见 [DOCKER.md](DOCKER.md)。

### 装信任（Windows）

`
python bequiet_proxy.py --install-ca      :: 把 "bequiet MITM CA" 装进 CurrentUser\Root
python bequiet_proxy.py --uninstall-ca    :: 卸载
`

> CA 只对**当前用户**的程序生效（CurrentUser 存储区）。随时可以用
> `--uninstall-ca` 撤销。

## 使用

`
:: HTTP 代理
curl -x http://127.0.0.1:9090 http://example.com/
curl -x http://127.0.0.1:9090 https://example.com/

:: SOCKS5 代理（socks5h = 域名交给代理解析）
curl -x socks5h://127.0.0.1:1080 https://example.com/

:: 环境变量
set HTTPS_PROXY=http://127.0.0.1:9090
set HTTP_PROXY=http://127.0.0.1:9090
set ALL_PROXY=socks5h://127.0.0.1:1080
`

**浏览器**：把 HTTP/HTTPS 代理指向 `127.0.0.1:9090` 即可。Chrome、Edge、Firefox 都走系统信任库，
执行过 `--install-ca` 后无需再单独导入证书。

不想动系统信任库的话，可以单独指定 CA 文件：

`
curl --cacert ca\ca.crt -x http://127.0.0.1:9090 https://example.com/
`

## 命令行参数

`
--http-port <n>       HTTP 代理端口（默认 9090）
--socks-port <n>      SOCKS5 代理端口（默认 1080）
--host <地址>         监听地址（默认 127.0.0.1）
--upstream <url>      上游服务（默认 https://bequiet.pages.dev）
--ca-dir <目录>       CA 存放目录（默认 ./ca）
--ca-cert/--ca-key    指定已有 CA，替代 --ca-dir 里的那份
--crl-url <url>       客户端获取 CRL 的地址（默认 http://<host>:<http-port>/bequiet-ca.crl）
--socks-auth 用户:密码  SOCKS5 强制用户名/密码认证
--socks-tls auto|always|never
                      SOCKS5 的 TLS 判定方式（auto = 端口 443/8443/9443）
--install-ca          把 CA 装进当前用户信任库
--uninstall-ca        从当前用户信任库移除 CA
-v, --verbose         打印每一条请求
--version             显示版本号
`

同样的参数也可以用环境变量给：

`
BEQUIET_HTTP_PORT / BEQUIET_SOCKS_PORT / BEQUIET_HOST / BEQUIET_UPSTREAM
BEQUIET_CA_DIR / BEQUIET_CRL_URL
`

## 工作原理

* **HTTP 代理**：absolute-form 请求（`GET http://host/path`）会被转发成
  `https://bequiet.pages.dev/fonts/http://host/path`。`CONNECT host:443` 先回
  `200 Connection Established`，再用本地 CA 现场签发的叶子证书在本地终结 TLS。
* **SOCKS5**：支持 `CONNECT`，可选无认证或用户名/密码认证。目标域名**不在本地解析**，
  所以天然具备 `socks5h` 的语义。
* **WebSocket / WSS**：MITM 握手完成后，把 `Upgrade: websocket` 请求重放为
  `wss://bequiet.pages.dev/fonts/wss://host/path`，之后双向转发帧
  （朝上游方向会重新加掩码，因为在那边我们是客户端）。
* **吊销列表（CRL）**：Windows 的 schannel 会拒绝拿不到吊销信息的证书
  （`CRYPT_E_NO_REVOCATION_CHECK`）。所以每张叶子证书都带一个 CRL 分发点，
  指向代理自己提供的 `http://127.0.0.1:9090/bequiet-ca.crl`；代理自己签发并对外提供这份 CRL。
* **上游健壮性**：上游偶尔会断连或挂起。代理对无 body 的请求（GET/HEAD）会在新连接上
  自动重试一次，复用连接前会先探测对端是否已关闭，超时则返回 504 而不是一直挂着。

## 关于 CA

**每台设备各自生成，不是写死的。**

首次运行时，`ca/` 目录里还没有证书，于是现场生成一份（ECDSA P-256）；之后每次启动都会
直接加载同一份，指纹不变——所以信任只需要装一次。

| 文件 | 作用 |
|---|---|
| `ca/ca.crt` | 根证书（公开，可分发） |
| `ca/ca.key` | 根私钥（**绝对不能提交或分发**） |
| `ca/ca.cer` | 根证书的 DER 形式，供 `certutil` 使用 |
| `ca/leaves/` | 运行时签发的叶子证书缓存 |

`ca/` 已经在 `.gitignore` 里，不会进仓库。

想查指纹：

`
python bequiet_proxy.py --install-ca
`

多台设备共用一套 CA（只装一次信任）：

`
python bequiet_proxy.py --ca-cert D:\shared\ca.crt --ca-key D:\shared\ca.key --install-ca
`

## 已知限制（都来自上游服务）

* 上游**没有 HEAD 处理**，永远不会响应。代理的做法是改用 GET 再丢掉响应体，
  所以 `HEAD` 经过代理仍然可用。
* 部分源站会让上游 Worker 抛异常（HTTP 500，`Worker threw exception` / 错误码 1101）。
  实测 **Cloudflare 托管的源站**会这样：`example.com`、`www.cloudflare.com` 失败，
  而 `duckduckgo.com`、`github.com`、`httpbin.org` 正常。代理会把上游的错误原样透传，
  客户端看到的是上游自己的 500 页面，而不是代理报错。
* 只支持 `wss://` 的 WebSocket 目标（`ws://` 会被上游拒绝）。
* CRL 由代理自己的 HTTP 端口提供。如果改了 `--http-port`，要重启代理，
  让新签发的叶子证书带上新的 CRL 地址。
* 冷门方法（`CONNECT`、`TRACE` 等）上游不支持。

## 目录结构

`
bequiet_proxy.py              单文件实现（仅标准库）
Dockerfile                    镜像定义
docker-compose.yml            编排：本地构建
docker-compose.ghcr.yml       编排：直接拉取 GHCR 镜像
.github/workflows/docker.yml  CI：构建多架构镜像并推送到 GHCR
start.cmd                     Windows 一键启动
ca/                           运行时生成的 CA（已在 .gitignore 中）
`

> 本发布包不含测试脚本，也不含 CA 目录。`ca/` 会在首次启动时自动生成，
> 且**每台设备各不相同**——不要把某一台机器的 `ca/` 复制给别的机器。

## 自测

测试脚本放在上游仓库的 `tests/` 目录下，本发布包未附带。需要自测时：

`
python bequiet_proxy.py --http-port 9090 --socks-port 1080
python tests/test.py      # HTTP 代理、SOCKS5、POST 请求体、WebSocket
python tests/test2.py     # 真实站点、流式响应、明文 HTTP、HEAD
`

## 镜像与 GitHub Actions

仓库内置 `.github/workflows/docker.yml`，在 push 到 `main`、打 `v*` 标签、
或手动触发时：

1. 先跑一遍端到端测试；
2. 构建 `linux/amd64` 与 `linux/arm64` 多架构镜像；
3. 推送到 GitHub Container Registry：`ghcr.io/<仓库名>`。

镜像标签：

| 标签 | 含义 |
|---|---|
| `latest` | 默认分支的最新版本 |
| `v1.2.3` | 对应的 git 标签 |
| `main` / `master` | 对应分支 |
| `<commit sha>` | 精确到提交 |

首次使用需要在仓库里开启 Actions 权限：**Settings → Actions → General → Workflow permissions
→ Read and write permissions**。`GITHUB_TOKEN` 自带 `packages: write`，不需要额外配置密钥。

本地拉取运行：

`
docker pull ghcr.io/<所有者>/<仓库名>:latest
docker run -d --name bequiet-proxy -p 9090:9090 -p 1080:1080 ^
  -v ./ca:/app/ca ^
  -e BEQUIET_CRL_URL=http://127.0.0.1:9090/bequiet-ca.crl ^
  ghcr.io/<所有者>/<仓库名>:latest
`

## 常见问题

**Q：浏览器提示证书错误？**
A：先确认已经执行 `--install-ca`，并且代理正在运行——CRL 需要从代理那里取。

**Q：CRL 地址打不开？**
A：`http://127.0.0.1:9090/bequiet-ca.crl` 是二进制 DER 文件，浏览器会**下载**而不是渲染，
这属于正常现象。想看内容：

`
curl -o crl.der http://127.0.0.1:9090/bequiet-ca.crl
certutil -dump crl.der
`

**Q：换了端口要重装信任吗？**
A：不用。换端口后 CRL 地址会自动跟着变（`--crl-url` 可手动指定），
根 CA 指纹不变，信任库照旧有效。

**Q：能不能给别的机器用？**
A：可以，用 `--host 0.0.0.0` 监听所有网卡，并把 `--crl-url` 改成客户端能访问到的地址
（IP 或主机名）。注意代理必须保持运行，CRL 是由它自己提供的。

**Q：Python 程序连本机代理报 `RemoteDisconnected`？**
A：多半不是代理的问题。Python 的 `urllib` 会读取 **Windows 注册表**里的系统代理设置
（`Internet Settings\ProxyServer`），连 `127.0.0.1` 的请求也会被发给那个系统代理。
绕过方式（任选其一）：

```
set NO_PROXY=127.0.0.1,localhost
# 或在代码里禁用代理
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
```

curl 和浏览器默认都会绕过本机地址，一般不受影响。

**Q：提示「端口已被占用」怎么办？**
A：换端口即可，例如 `--http-port 9191 --socks-port 1181`。代理不会去抢占已被占用的端口
（Windows 下使用 `SO_EXCLUSIVEADDRUSE`）。
