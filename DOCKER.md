# Docker 部署

bequiet-proxy 的 Docker 封装。镜像里只有 `bequiet_proxy.py` 一个文件，
**容器内不需要构建，也不需要 pip 安装**。

| 文件 | 用途 |
|---|---|
| `Dockerfile` | 镜像定义（基于 `python:3.12-slim`） |
| `docker-compose.yml` | 本地构建 + 运行 |
| `docker-compose.ghcr.yml` | 直接拉取 GHCR 上已发布的镜像 |
| `.github/workflows/docker.yml` | CI：测试 + 构建多架构镜像 + 推送 GHCR |
| `.dockerignore` | 排除 `ca/` 等，确保私钥不进镜像 |

## 快速开始

`
:: 构建并启动
docker compose up -d

:: 看日志
docker compose logs -f

:: 把 CA 装进本机信任库（读 ./ca，与容器共用同一份证书）
python bequiet_proxy.py --install-ca --ca-dir ./ca

:: 用起来
curl -x http://127.0.0.1:9090 http://httpbin.org/get
curl -x socks5h://127.0.0.1:1080 https://duckduckgo.com/
`

不用 compose 的话：

`
docker build -t bequiet-proxy .
docker run -d --name bequiet-proxy ^
  -p 9090:9090 -p 1080:1080 ^
  -v ./ca:/app/ca ^
  -e BEQUIET_CRL_URL=http://127.0.0.1:9090/bequiet-ca.crl ^
  bequiet-proxy
`

## CA 在容器里怎么工作

CA 是在**容器首次启动时**生成的，写进 `/app/ca`——而这个目录是宿主机上的 bind mount（`./ca`）。
这样宿主机和容器永远用的是同一张根证书，宿主机信任一次就够了：

1. `docker compose up -d` —— 容器创建 `./ca/ca.crt`、`./ca/ca.key` 等文件；
2. `python bequiet_proxy.py --install-ca --ca-dir ./ca` —— 把它装进 `CurrentUser\Root`；
3. 之后无论重启还是重建镜像，CA 都不变，信任一直有效。

容器以非 root 用户（uid 10001）运行，`.dockerignore` 里排除了 `ca/`，
所以**私钥绝不会被打进镜像**。

## 关键点：CRL 必须对客户端可达

Windows schannel 拿不到吊销信息就会拒绝证书（`CRYPT_E_NO_REVOCATION_CHECK`）。
每张叶子证书都带一个 CRL 分发点，而这份 CRL 是代理自己提供、自己签名的。

写进叶子证书的 URL 必须**客户端访问得到**——容器里的 `127.0.0.1` 对容器外的客户端没意义。
这就是 `BEQUIET_CRL_URL` 的用途：

| 客户端位置 | 取值 |
|---|---|
| 和 Docker 同机 | `http://127.0.0.1:<发布的 HTTP 端口>/bequiet-ca.crl` |
| 局域网另一台机器 | `http://<宿主机内网 IP>:<发布的 HTTP 端口>/bequiet-ca.crl` |
| 同一个 compose 网络内 | `http://bequiet-proxy:9090/bequiet-ca.crl` |

`BEQUIET_CRL_URL` 必须和**客户端实际连的端口**一致。如果把 HTTP 代理发布到 9090 以外的端口，
两个要一起改：

`
set BEQUIET_HTTP_PORT=9090
docker compose up -d
`

compose 文件已经处理好了：`BEQUIET_CRL_URL` 由 `BEQUIET_HTTP_PORT` 拼出来，
所以默认的 `127.0.0.1:9090` 永远和本机客户端看到的一致。

按客户端视角验证 CRL 是否可达：

`
curl -o crl.der http://127.0.0.1:9090/bequiet-ca.crl
certutil -dump crl.der
`

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `BEQUIET_HOST` | 0.0.0.0 | 容器内监听地址 |
| `BEQUIET_HTTP_PORT` | 9090 | 容器内 HTTP 代理端口 |
| `BEQUIET_SOCKS_PORT` | 1080 | 容器内 SOCKS5 代理端口 |
| `BEQUIET_CRL_URL` | http://<host>:<http-port>/bequiet-ca.crl | 客户端获取 CRL 的地址 |
| `BEQUIET_CA_DIR` | /app/ca | CA 存放目录 |
| `BEQUIET_UPSTREAM` | https://bequiet.pages.dev | 上游服务 |

## 镜像标签与 GHCR

`.github/workflows/docker.yml` 会在 push 到 `main`、打 `v*` 标签或手动触发时：

1. 跑一遍端到端测试（真实连上游）；
2. 构建 `linux/amd64` + `linux/arm64`（纯 Python，两个架构通用）；
3. 推送到 `ghcr.io/<仓库名>`。

标签规则：

| 标签 | 含义 |
|---|---|
| `latest` | 默认分支最新 |
| `v1.2.3` | git 标签 |
| `main` / `master` | 分支 |
| `<sha>` | 精确提交 |

仓库需要在 **Settings → Actions → General → Workflow permissions** 里勾选
*Read and write permissions*。`GITHUB_TOKEN` 自带 `packages: write`，不需要额外密钥。

PR 只构建不推送（`push` 的条件是 `github.event_name != 'pull_request'`）。

拉取运行：

`
docker pull ghcr.io/<所有者>/<仓库名>:latest
docker run -d --name bequiet-proxy -p 9090:9090 -p 1080:1080 ^
  -v ./ca:/app/ca ^
  -e BEQUIET_CRL_URL=http://127.0.0.1:9090/bequiet-ca.crl ^
  ghcr.io/<所有者>/<仓库名>:latest
`

或者改用 `docker-compose.ghcr.yml`（记得把里面的 `image` 改成你的实际仓库名）：

`
docker compose -f docker-compose.ghcr.yml up -d
`

## 安全加固

compose 里已经启用：

* 非 root 用户运行（uid 10001）；
* `cap_drop: ALL`——代理不需要任何 capability；
* `no-new-privileges:true`；
* `.dockerignore` 排除 `ca/`，私钥不进镜像、不进仓库。

## 排错

**容器起不来，日志报端口占用**
A：改宿主机端口，`set BEQUIET_HTTP_PORT=9090` 后再 `docker compose up -d`；
注意 `BEQUIET_CRL_URL` 会自动跟着变。

**浏览器报证书错误**
A：CRL 没取到。确认客户端能访问 `BEQUIET_CRL_URL` 指向的地址，且代理还在运行。

**改端口后信任失效**
A：不会。根 CA 指纹不变，只是叶子证书里的 CRL 地址变了，代理重启后会重新签发。

**容器里的 `ca/` 权限报错**
A：宿主机那个目录对 uid 10001 不可写。删掉目录重建，或
`docker run --user 0 ...`（不推荐）。
