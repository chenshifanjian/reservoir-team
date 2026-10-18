# 模型蓄水池 · 组队协调服务（Reservoir Team Coordinator）

给 [模型蓄水池](https://github.com/chenshifanjian/model-reservoir) 提供**组队**功能的协调服务器。

它的唯一职责是当一个**加密信箱**：存队伍状态、成员表、以及队长推来的**密文**密钥包。

> ⚠️ **这个服务是完全可选的。**
> 模型蓄水池桌面端在没有它的情况下，所有其他功能（多上游聚合、OpenAI 兼容接口、
> 模型管理、稳定性监控、调用日志、一键配置）全部正常工作。
> 只有「组队」这一个功能需要它，而组队本身也是可选的。

## 它做什么 / 不做什么

| 做 | 不做 |
| --- | --- |
| 建队 / 生成组队码 | **不解密任何密文** |
| 队员输码入队、队长审批 | 不转发模型对话（模型调用直连上游） |
| 存队长推来的**密文**密钥包，按成员分发 | 不限制用量、不审计内容 |
| 统计上报的用量数字（时间/模型/token 数） | 不持有任何上游 API key |
| 关队、踢人、队伍过期清理 | — |

**服务端代码里没有解密能力** —— `coordinator.py` 不 import `cryptography`。
密钥在客户端用组队码派生的密钥加密后才上传。

模型的实际调用**不经过这台服务器**：队员解密出上游配置后，直连上游 API。
协调服务器挂了，已经同步过的队伍照样能用，只是不能再审批新成员或改昵称。

## 依赖

- Python 3.11+（只用标准库，不需要 fastapi/uvicorn）
- `cryptography` 包（用于 scrypt 校验入队码；**不用于解密**）
- 一台有公网 IP 的 Linux，root 权限

实测资源占用：**约 13–15 MiB 常驻内存**，可以在 512 MiB 可用内存的小机器上稳跑。

## 部署

```bash
# 在你本机跑，脚本通过 SSH 把服务推到目标机
SSHPASS='<目标机root口令>' TEAM_HOST='<你的服务器IP>' bash deploy.sh
```

可选环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `TEAM_HOST` | 必填 | 目标机 IP 或域名 |
| `TEAM_SSH_PORT` | `22` | SSH 端口 |
| `TEAM_PORT` | `5022` | 协调服务监听端口 |
| `TEAM_DIR` | `/opt/reservoir-team` | 远端安装目录 |

脚本**幂等**：重复运行只覆盖代码并重启服务，数据库不动。
装完会自动做健康检查、代码版本自检、内存占用确认。

目标机若没有 `cryptography`：

```bash
python3 -m pip install --break-system-packages cryptography
```

### 手动部署

```bash
# 1) 放文件
scp coordinator.py protocol.py root@<你的机器>:/opt/reservoir-team/
scp reservoir-team.service root@<你的机器>:/etc/systemd/system/

# 2) 装依赖
ssh root@<你的机器> 'python3 -m pip install --break-system-packages cryptography'

# 3) 启动（注意：必须 restart，enable --now 不会重启已运行的进程）
ssh root@<你的机器> 'systemctl daemon-reload && systemctl enable --now reservoir-team'

# 4) 验证
ssh root@<你的机器> 'curl -s http://127.0.0.1:5022/health'
```

## 套上 HTTPS（必须）

协调服务只监听 `127.0.0.1`，不直接暴露公网。请在前面加一层 nginx 反代并终结 TLS。

参考配置：[`nginx-reservoir-team.conf`](./nginx-reservoir-team.conf)

> ⚠️ **两个必踩的坑**（本项目实际踩过）：
>
> **① 上游协议必须写 `http://`，不是 `https://`**
> TLS 在 nginx 这层终结，后端是明文 HTTP。写成 `https://127.0.0.1:5022` 会得到
> 「回环 200、公网 502」的诡异现象 —— 服务明明活着、本地 curl 正常，但外网访问全部 502。
> 判断依据：nginx error log 里 `upstream: "https://..."`。
> 如果非要写 https，还得额外去掉 `proxy_ssl_server_name`。
>
> **② 如果用 1Panel，它的配置是「双写」的**
> 同一份配置同时存在文件系统 `<站点目录>/proxy/*.conf` 和面板数据库里。
> 只改文件系统的话，下次在面板点保存会被覆盖回去。
> 所以建站点请走面板；手工改文件只适合临时调试。改完记得 `nginx -t` 再 reload。

验证：

```bash
curl -s https://<你的域名>/health
# 期望：{"ok": true, "service": "reservoir-team", "ts": ...}
```

## 让客户端连上你的服务器

模型蓄水池桌面端的「组队」页里有一个**协调服务器**输入框，
默认填的是项目方维护的服务器。把它改成你自己的地址，回车即可。

改完后客户端会保存这个设置，之后建队/入队都走你的服务器。

## systemd 加固

[`reservoir-team.service`](./reservoir-team.service) 已带这些加固（可直接用）：

| 项 | 值 | 为什么 |
| --- | --- | --- |
| `MemoryMax` | `128M` | 服务实际只吃 ~15MiB；超了被 OOM 杀掉重启，而不是拖垮同机其他服务 |
| `ProtectSystem` | `strict` | 只能写自己的数据目录 |
| `NoNewPrivileges` | `true` | 它不需要任何特权 |
| `PrivateTmp` / `PrivateDevices` | `true` | 隔离 |
| `Restart` | `on-failure` | 崩了自愈 |

数据落在 `team.db`（SQLite，WAL 模式）。备份就拷这一个文件。

## HTTP API

全部 JSON。除 `/health` 外都需要 `Authorization: Bearer <token>`，
token 由建队/入队时服务端下发。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查（免鉴权） |
| `POST` | `/api/teams` | 建队。body: `captain_client_id`, `code_hash`, `code_salt`, `ttl`, `nickname` → 返回 `team_id` + 成员 `token` |
| `POST` | `/api/teams/join` | 输码入队。body: `team_id`, `code_hash`, `client_id`, `nickname` → 返回 `code_salt`（客户端据此派生密钥）+ 成员 `token` |
| `POST` | `/api/teams/<id>/approve` | 队长批准成员（仅队长） |
| `POST` | `/api/teams/<id>/kick` | 队长移出成员（仅队长） |
| `POST` | `/api/teams/<id>/close` | 队长关队（仅队长）。之后码立即失效，队员自动置灰 |
| `POST` | `/api/teams/<id>/rotate` | 队长换码（旧码立即作废） |
| `POST` | `/api/teams/<id>/nickname` | 改自己昵称 |
| `POST` | `/api/teams/<id>/packages` | 队长推**密文**密钥包（仅队长）。body: `{target_client_id, provider_name, nonce, payload}` |
| `GET` | `/api/teams/<id>/packages` | 队员拉自己的密文包 |
| `POST` | `/api/teams/<id>/usage` | 上报用量数字（不含对话内容） |
| `GET` | `/api/teams/<id>/state` | 拉队伍状态 + 成员表 + 自己是否还被认可 |
| `GET` | `/api/teams/<id>/usage` | 队长看分人/分模型统计（仅队长） |

### 限制（防滥用）

| 项 | 值 |
| --- | --- |
| 请求体上限 | 1 MB |
| 队伍默认有效期 | 7 天（上限 30 天），到期自动清理 |
| 错码尝试 | 每队每 IP 5 次，锁 3600 秒 |
| 建队频率 | 每 IP 每小时 20 次 |
| 单队成员上限 | 32 |
| 每成员最多收包 | 64 |
| 单次用量上报 | 200 条 |
| 昵称长度 | ≤ 32 字符 |

## 协议与安全模型

密钥派生实现在 [`protocol.py`](./protocol.py) —— **这是协议的权威定义**。
客户端仓库里有一份相同副本，两边必须保持一致（见下文「协议漂移防护」）。

```
K_team   = scrypt(组队码 ‖ team_id, salt, N=2^15, r=8, p=1)   # dklen=32
K_member = HKDF(K_team, salt=None, info=member_id, dklen=32)
密文     = AESGCM-256(K_member, nonce=os.urandom(12), aad=None)
```

服务端**只存** `code_salt`（明文，用于派生）和 `code_hash`（scrypt 结果，用于验码）。
服务端**不存** `K_team` / `K_member`，**也不需要** —— 它只搬运密文。

### 组队码形态

- **8 位高熵码（默认）**：字母表 `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`（去掉易混的 0/O/1/I），
  约 2^40 种
- **6 位数字码（低安全档）**：约 2^20 种

6 位码的离线爆破成本约 19 核·小时/队（scrypt N=2^15 实测 67.6 ms/次），
数据库一旦泄漏，租几十个 vCPU 几十分钟就能解出全部成员的密钥。
**所以默认用 8 位码**，6 位只作为临时低安全档保留。

### 已知的安全边界

- **同步即复制密钥**：密钥一旦解密写进队员机器，**无法远程收回**。
  队长能做的只有关队（之后队员那边的上游会被置灰、模型全禁用），
  真正的补救是**你自己去上游控制台换 Key**。
- **被踢成员仍持有 `K_team`**：可以解后续推给其他成员的新包。
  服务端有 `rotate_code` 端点可用于轮换，但客户端目前未接线。
- **join 会把明文组队码发给服务端**：服务端不存储，但活着的服务器在内存里能看到。
  （`code_salt` 本就不保密，真正需要保密的只有码本身。）

## 协议漂移防护

`protocol.py` 是客户端与服务端共用的密钥派生实现。两份副本必须字节一致，
否则会出现「客户端加密、服务端验不过码」的故障。

```bash
# 对比两边的 protocol.py
sha256sum protocol.py
# 客户端仓库：https://github.com/chenshifanjian/model-reservoir
```

**改 `protocol.py` 时，两个仓库必须同时改、同时发版。**

## 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 公网 502，回环 200 | 反代上游协议写成了 `https://` | 改成 `http://`，reload |
| 客户端拿不到 `code_salt` | 跑的是旧版 coordinator | `systemctl restart reservoir-team` |
| 队员拉包为空 | 队长没勾选该上游 / 队伍已关 | 队长检查「同步」勾选；确认队伍状态 |
| 服务起不来 | 端口被占 / 缺 cryptography | `journalctl -u reservoir-team -n 20 --no-pager` |
| 内存被 OOM 杀 | 上游反代配置错误导致堆积 | 看 journal；`MemoryMax=128M` 是保险丝 |

日志：`journalctl -u reservoir-team -f`

## 相关项目

- [模型蓄水池](https://github.com/chenshifanjian/model-reservoir) —— 桌面端，
  多家 LLM 提供商额度聚合成 OpenAI 兼容接口。本仓库是它的可选配套服务端。

## 许可证

**CC BY-NC 4.0**（署名 + 非商业），与客户端仓库一致。

模型蓄水池 fork 自 [zk-2025/model-gateway](https://github.com/zk-2025/model-gateway)
（原作者已声明项目终止、转向收费版并删除源码）。本 fork 从 git 历史恢复完整源码，
2026-10-03 原作者已书面授权二次开发并开源，原作者署名保留。

**若要用它做商业服务，需先取得原作者授权。**
