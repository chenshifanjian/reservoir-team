#!/usr/bin/env python3
"""model-reservoir 组队协调服务（阿里云边缘机专用）

设计原则：**阿里云只见密文与状态，永不见明文密钥，也不见对话内容。**

    队长客户端 ──建立队伍/上传密文包──▶ 本服务（SQLite）
    队员客户端 ◀──拉状态/拉密文包────      只存：队伍、成员、密文包、用量数字
          │                              永不存：明文密钥、对话内容
          └──解密后写入自己的 providers.json

依赖：仅 Python 标准库 + cryptography（机器上已装 38.0.4）。不装 fastapi/uvicorn ——
那台机只有 505Mi 可用内存。流量极小（建队/审批/轮询），标准库 HTTP server 足够。

运行：python3 coordinator.py /path/to/data.db [port]
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import signal
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# 注意：本服务**不 import AESGCM**，也不持有任何解密能力。
# 端到端加密意味着密文在客户端加密、客户端解密，服务端只当中转信箱 ——
# 这正是「阿里云永不见明文密钥」的保证（ruff F401 会一直提醒这件事，保留注释说明）。

# 密钥派生参数与客户端共用同一份实现，避免两边漂移
# （protocol.py 与本文件一起部署到 /opt/reservoir-team/）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from protocol import code_hash as _protocol_code_hash, SCRYPT_N, SCRYPT_R, SCRYPT_P, MAXMEM
except ImportError:                      # 独立运行时兜底（如单文件拷走测试）
    SCRYPT_N = 2 ** 15
    SCRYPT_R = 8
    SCRYPT_P = 1
    MAXMEM = 64 * 1024 * 1024

    def _protocol_code_hash(code: str, salt_hex: str) -> str:
        return hashlib.scrypt(code.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                              n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                              dklen=32, maxmem=MAXMEM).hex()

CODE_TTL_DEFAULT = 7 * 86400      # 队伍默认 7 天，到期自动失效（配合防离线枚举）
MAX_JOIN_ATTEMPTS = 5             # 每队每 IP 允许的错码次数
JOIN_LOCK_SECONDS = 3600          # 锁定时长
MAX_PACKAGES_PER_MEMBER = 64      # 每个队员最多收多少密文包
MAX_USAGE_BATCH = 200             # 单次上报用量条数上限
MAX_NICKNAME_LEN = 32
MAX_PROVIDER_NAME_LEN = 64
MAX_MEMBERS_PER_TEAM = 32      # 单队成员上限（防无限加人堆数据）
MAX_TEAMS_PER_IP_HOUR = 20     # 每 IP 每小时建队上限（防无限建队堆数据）
TEAM_TTL_MIN = 300             # 最短 5 分钟（负数/0 会建出即过期的废队伍）
TEAM_TTL_MAX = 30 * 86400      # 最长 30 天

DB_LOCK = threading.Lock()

# 协调服务的存储单例：main() 启动时注入，之后只读引用。
# 用模块级变量而非类属性，避免类型检查器把 None 当成可下标对象。
_store: "Store | None" = None


# 组队码的合法形态：6 位数字，或 8 位高熵码（与 team_client 的字母表一致，
# 去掉易混的 0/O/1/I）。长度上限挡的是畸形输入 —— 真正的安全来自 scrypt 比对。
CODE_LEN_6 = 6
CODE_LEN_8 = 8
CODE_ALPHABET_8 = set("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")


def _valid_code(code: str) -> bool:
    """入队码形态校验。"""
    if len(code) == CODE_LEN_6:
        return code.isdigit()
    if len(code) == CODE_LEN_8:
        return all(c in CODE_ALPHABET_8 for c in code)
    return False


def scrypt_key(password: str, salt_hex: str) -> str:
    """入队码校验摘要。服务端只存这个，从不持有明文码 → 也派生不出队伍密钥。"""
    return _protocol_code_hash(password, salt_hex)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------- 数据库 ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS teams (
    team_id            TEXT PRIMARY KEY,
    captain_client_id  TEXT NOT NULL,
    code_hash          TEXT NOT NULL,
    code_salt          TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'open',   -- open | closed
    created_at         REAL NOT NULL,
    expires_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    team_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    nickname    TEXT NOT NULL,
    role        TEXT NOT NULL,                        -- captain | member
    status      TEXT NOT NULL,                        -- pending | approved | kicked
    token_hash  TEXT NOT NULL,
    joined_at   REAL NOT NULL,
    PRIMARY KEY (team_id, client_id)
);
CREATE TABLE IF NOT EXISTS packages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id           TEXT NOT NULL,
    target_client_id  TEXT NOT NULL,
    provider_name     TEXT NOT NULL,
    payload           BLOB NOT NULL,                  -- AESGCM 密文
    nonce             BLOB NOT NULL,
    contributor_client_id TEXT NOT NULL DEFAULT '',   -- 谁贡献的（共享池要显示「来自谁」）
    created_at        REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id   TEXT NOT NULL,
    client_id TEXT NOT NULL,
    ts        REAL NOT NULL,
    provider  TEXT NOT NULL,
    model     TEXT NOT NULL,
    pt        INTEGER NOT NULL,
    ct        INTEGER NOT NULL,
    tt        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS join_attempts (
    team_id TEXT NOT NULL,
    ip      TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS create_attempts (
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pkg_target ON packages(team_id, target_client_id);
CREATE INDEX IF NOT EXISTS idx_pkg_contrib ON packages(team_id, contributor_client_id);
CREATE INDEX IF NOT EXISTS idx_usage_team ON usage_log(team_id, client_id);
CREATE INDEX IF NOT EXISTS idx_attempt ON join_attempts(team_id, ip, ts);
CREATE INDEX IF NOT EXISTS idx_create ON create_attempts(ip, ts);
"""


def team_expired(team) -> bool:
    """队伍是否已过期。

    expires_at == 0 表示**永久队伍**，永不判过期。
    这个判定必须集中在这里：散落的 `time.time() > expires_at`
    在永久队伍上永远为真（now > 0），会把好好的队伍判死。
    """
    if not team:
        return True
    exp = team["expires_at"]
    return exp > 0 and time.time() > exp


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        with DB_LOCK:
            # 顺序要紧：先补列再跑 SCHEMA。SCHEMA 里有针对新列的
            # CREATE INDEX，反过来会让没有该列的老库直接 no such column 崩掉。
            self._migrate()
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def _migrate(self):
        """老库补列。CREATE TABLE IF NOT EXISTS 不会给已有表加列，
        所以升级部署必须单独补 —— 否则线上老库插入会直接报错。"""
        # PRAGMA 对不存在的表**不抛异常，返回空集**，所以只能看行数，
        # 用 try/except 抓不到「表还不存在」这种情况。
        rows = self.conn.execute("PRAGMA table_info(packages)").fetchall()
        if not rows:
            return        # 全新库，表还不存在，下面 SCHEMA 会建
        cols = {r["name"] for r in rows}
        if "contributor_client_id" not in cols:
            self.conn.execute(
                "ALTER TABLE packages ADD COLUMN contributor_client_id "
                "TEXT NOT NULL DEFAULT ''")

    # ---- 限流 ----
    def check_rate_limit(self, team_id: str, ip: str) -> bool:
        """返回 True = 允许尝试；False = 已锁。"""
        now = time.time()
        with DB_LOCK:
            rows = self.conn.execute(
                "SELECT ts FROM join_attempts WHERE team_id=? AND ip=? AND ts>? ",
                (team_id, ip, now - JOIN_LOCK_SECONDS),
            ).fetchall()
        return len(rows) < MAX_JOIN_ATTEMPTS

    def record_attempt(self, team_id: str, ip: str):
        with DB_LOCK:
            self.conn.execute(
                "INSERT INTO join_attempts(team_id, ip, ts) VALUES(?,?,?)",
                (team_id, ip, time.time()),
            )
            self.conn.execute(
                "DELETE FROM join_attempts WHERE ts < ?", (time.time() - 86400,)
            )
            self.conn.commit()

    def check_create_limit(self, ip: str) -> bool:
        """每 IP 每小时允许的建队次数。True = 放行。"""
        now = time.time()
        with DB_LOCK:
            n = self.conn.execute(
                "SELECT COUNT(*) c FROM create_attempts WHERE ip=? AND ts>?",
                (ip, now - 3600),
            ).fetchone()["c"]
        return n < MAX_TEAMS_PER_IP_HOUR

    def record_create(self, ip: str):
        with DB_LOCK:
            self.conn.execute(
                "INSERT INTO create_attempts(ip, ts) VALUES(?,?)", (ip, time.time()))
            self.conn.execute(
                "DELETE FROM create_attempts WHERE ts < ?", (time.time() - 86400,))
            self.conn.commit()

    def count_members(self, team_id: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) c FROM members WHERE team_id=?", (team_id,)).fetchone()["c"]

    def purge_expired(self):
        """删掉过期队伍及其成员/密文包/用量。过期数据不清理会让数据库无限增长，
        也让「7 天 TTL 防离线枚举」失效（拿得到 db 文件就仍能离线破解）。"""
        now = time.time()
        with DB_LOCK:
            ids = [r["team_id"] for r in self.conn.execute(
                # expires_at=0 是永久队伍，不能进清理列表
                "SELECT team_id FROM teams WHERE expires_at > 0 AND expires_at < ?",
                (now,)).fetchall()]
            for tid in ids:
                self.conn.execute("DELETE FROM members WHERE team_id=?", (tid,))
                self.conn.execute("DELETE FROM packages WHERE team_id=?", (tid,))
                self.conn.execute("DELETE FROM usage_log WHERE team_id=?", (tid,))
                self.conn.execute("DELETE FROM teams WHERE team_id=?", (tid,))
            if ids:
                self.conn.commit()
        return len(ids)

    def clear_attempts(self, team_id: str, ip: str):
        with DB_LOCK:
            self.conn.execute(
                "DELETE FROM join_attempts WHERE team_id=? AND ip=?", (team_id, ip)
            )
            self.conn.commit()

    # ---- 队伍 ----
    def create_team(self, team_id, captain_client_id, code_hash, code_salt, ttl,
                    permanent=False):
        now = time.time()
        with DB_LOCK:
            self.conn.execute(
                "INSERT INTO teams(team_id,captain_client_id,code_hash,code_salt,"
                "status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                (team_id, captain_client_id, code_hash, code_salt, "open", now,
                 0 if permanent else now + ttl),   # expires_at=0 表示永久
            )
            self.conn.commit()

    def get_team(self, team_id):
        row = self.conn.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
        return dict(row) if row else None

    def close_team(self, team_id):
        with DB_LOCK:
            self.conn.execute("UPDATE teams SET status='closed' WHERE team_id=?", (team_id,))
            self.conn.commit()

    def rotate_code(self, team_id, code_hash, code_salt):
        with DB_LOCK:
            self.conn.execute(
                "UPDATE teams SET code_hash=?, code_salt=? WHERE team_id=?",
                (code_hash, code_salt, team_id),
            )
            self.conn.commit()

    # ---- 成员 ----
    def add_member(self, team_id, client_id, nickname, role, status, token_hash):
        with DB_LOCK:
            self.conn.execute(
                "INSERT OR REPLACE INTO members(team_id,client_id,nickname,role,status,"
                "token_hash,joined_at) VALUES(?,?,?,?,?,?,?)",
                (team_id, client_id, nickname, role, status, token_hash, time.time()),
            )
            self.conn.commit()

    def get_member(self, team_id, client_id):
        row = self.conn.execute(
            "SELECT * FROM members WHERE team_id=? AND client_id=?", (team_id, client_id)
        ).fetchone()
        return dict(row) if row else None

    def find_by_token(self, team_id, token_hash):
        row = self.conn.execute(
            "SELECT * FROM members WHERE team_id=? AND token_hash=?", (team_id, token_hash)
        ).fetchone()
        return dict(row) if row else None

    def list_members(self, team_id):
        rows = self.conn.execute(
            "SELECT client_id,nickname,role,status,joined_at FROM members "
            "WHERE team_id=? ORDER BY joined_at", (team_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def set_member_status(self, team_id, client_id, status):
        with DB_LOCK:
            self.conn.execute(
                "UPDATE members SET status=? WHERE team_id=? AND client_id=?",
                (status, team_id, client_id),
            )
            self.conn.commit()

    def set_nickname(self, team_id, client_id, nickname):
        with DB_LOCK:
            self.conn.execute(
                "UPDATE members SET nickname=? WHERE team_id=? AND client_id=?",
                (nickname, team_id, client_id),
            )
            self.conn.commit()

    # ---- 密文包 ----
    def add_package(self, team_id, target_client_id, contributor_client_id,
                    provider_name, payload, nonce):
        with DB_LOCK:
            # 限额按**贡献者**算，不是按 target。广播包（target=''）是全队共享的，
            # 若按 target 计数，14 个人的广播包会挤进同一个 64 条的桶里被卡死。
            cnt = self.conn.execute(
                "SELECT COUNT(*) c FROM packages WHERE team_id=? AND contributor_client_id=?",
                (team_id, contributor_client_id),
            ).fetchone()["c"]
            if cnt >= MAX_PACKAGES_PER_MEMBER:
                return False
            self.conn.execute(
                "INSERT INTO packages(team_id,target_client_id,provider_name,payload,"
                "nonce,contributor_client_id,created_at) VALUES(?,?,?,?,?,?,?)",
                (team_id, target_client_id, provider_name, payload, nonce,
                 contributor_client_id, time.time()),
            )
            self.conn.commit()
        return True

    def list_packages(self, team_id, target_client_id):
        rows = self.conn.execute(
            # 广播包（target_client_id=''）全队都能取，定向包只给指定的人。
            # contributor 一并返回，UI 靠它显示「来自某某」。
            "SELECT provider_name,payload,nonce,contributor_client_id,created_at "
            "FROM packages "
            "WHERE team_id=? AND (target_client_id='' OR target_client_id=?)",
            (team_id, target_client_id)
        ).fetchall()
        return [dict(r) for r in rows]

    def count_packages(self, team_id):
        return self.conn.execute(
            "SELECT COUNT(*) c FROM packages WHERE team_id=?", (team_id,)
        ).fetchone()["c"]

    # ---- 用量 ----
    def add_usage(self, team_id, client_id, items):
        with DB_LOCK:
            self.conn.executemany(
                "INSERT INTO usage_log(team_id,client_id,ts,provider,model,pt,ct,tt) "
                "VALUES(?,?,?,?,?,?,?,?)",
                [(team_id, client_id, i["ts"], i["provider"], i["model"],
                  int(i["pt"]), int(i["ct"]), int(i["tt"])) for i in items],
            )
            self.conn.commit()

    def list_usage(self, team_id):
        rows = self.conn.execute(
            "SELECT client_id, SUM(pt) pt, SUM(ct) ct, SUM(tt) tt, COUNT(*) calls "
            "FROM usage_log WHERE team_id=? GROUP BY client_id", (team_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def usage_by_model(self, team_id):
        rows = self.conn.execute(
            "SELECT client_id, model, SUM(tt) tt, COUNT(*) calls FROM usage_log "
            "WHERE team_id=? GROUP BY client_id, model ORDER BY tt DESC",
            (team_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- HTTP 服务 ----------
def _json_body(handler) -> dict:
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > 1 << 20:      # 1MB 上限
        return {}
    try:
        raw = handler.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _send(handler, code: int, obj: dict):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    # 不发任何 CORS 头。桌面客户端是用后端 httpx 调这里，浏览器从不直接调，
    # 所以 Access-Control-Allow-Origin: * 只是多余的攻击面 —— 它会放行
    # 任意网页发起的跨域请求（带 Authorization 会走 preflight，而
    # Allow-Headers 明确放行了 Authorization）。鉴权仍然挡得住，但没必要开门。
    # 若将来真要做浏览器端的管理界面，再按具体 origin 收紧，不要用 *。
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "ReservoirTeam/1.0"
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args):
        """只记方法与路径，绝不记 body（body 里可能有密文与 token）。"""
        sys.stderr.write("%s %s %s\n" % (time.strftime("%H:%M:%S"),
                                         self.command, urlparse(self.path).path))

    # ---- 鉴权 ----
    def _auth(self, team_id: str, want_role: str | None = None):
        """返回 (member_dict, None) 或 (None, 错误码)"""
        hdr = self.headers.get("Authorization") or ""
        if not hdr.startswith("Bearer "):
            return None, 401
        token = hdr[7:].strip()
        if not token:
            return None, 401
        m = self.STORE().find_by_token(team_id, hash_token(token))
        if not m:
            return None, 401
        if want_role and m["role"] != want_role:
            return None, 403
        if m["status"] == "kicked":
            return None, 403
        return m, None

    def _team_open(self, team_id: str):
        t = self.STORE().get_team(team_id)
        if not t:
            return None, 404
        if t["status"] != "open" or team_expired(t):
            return None, 410          # Gone：队伍已关闭或过期
        return t, None

    def STORE(self) -> "Store":
        """取存储单例；未注入说明启动顺序有问题，直接失败而不是静默 None。"""
        if _store is None:
            raise RuntimeError("协调服务存储未初始化")
        return _store

    def do_OPTIONS(self):
        _send(self, 204, {})

    def do_GET(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]

        if parts[:1] == ["health"]:
            _send(self, 200, {"ok": True, "service": "reservoir-team", "ts": time.time()})
            return

        # /api/teams/<id>/state | /packages | /usage
        if len(parts) == 4 and parts[:2] == ["api", "teams"]:
            team_id, action = parts[2], parts[3]
            t, err = self._team_open(team_id)
            if err and action != "state":
                _send(self, err, {"ok": False, "error": "team_unavailable"})
                return
            m, err = self._auth(team_id)
            if err:
                _send(self, err, {"ok": False, "error": "unauthorized"})
                return

            if action == "state":
                # 队员轮询：拿队伍状态 + 成员表 + 自己是否还被认可
                team = self.STORE().get_team(team_id)
                alive = bool(team) and team["status"] == "open" and not team_expired(team)
                _send(self, 200, {
                    "ok": True, "alive": alive,
                    "status": team["status"] if team else "closed",
                    "members": self.STORE().list_members(team_id),
                    "me": {"client_id": m["client_id"], "nickname": m["nickname"],
                           "role": m["role"], "status": m["status"]},
                })
                return

            if action == "packages":
                pkgs = self.STORE().list_packages(team_id, m["client_id"])
                _send(self, 200, {"ok": True, "packages": [
                    {"provider_name": p["provider_name"],
                     "nonce": p["nonce"].hex(),
                     "payload": p["payload"].hex(),
                     "contributor_client_id": p["contributor_client_id"],
                     "created_at": p["created_at"]} for p in pkgs]})
                return

            if action == "usage":
                if m["role"] != "captain":
                    _send(self, 403, {"ok": False, "error": "captain_only"})
                    return
                _send(self, 200, {"ok": True, "by_member": self.STORE().list_usage(team_id),
                                  "by_model": self.STORE().usage_by_model(team_id)})
                return

        _send(self, 404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        body = _json_body(self)
        ip = self.client_address[0] if self.client_address else "?"

        # ---- /api/teams  建队 ----
        if parts == ["api", "teams"]:
            if not self.STORE().check_create_limit(ip):
                _send(self, 429, {"ok": False, "error": "too_many_teams",
                                  "retry_after": 3600})
                return
            team_id = secrets.token_hex(16)
            captain_client_id = str(body.get("captain_client_id") or "").strip()
            code_hash = str(body.get("code_hash") or "").strip()
            code_salt = str(body.get("code_salt") or "").strip()
            # ttl 必须是合法整数且落在区间内。
            # 直接 int() 会让 "abc" 抛 ValueError → 连接被掐断（RemoteDisconnected）；
            # 负数则建出即过期的废队伍。
            try:
                # 不能写成 `body.get("ttl") or CODE_TTL_DEFAULT`：
                # ttl=0 是「永久」的合法取值，而 0 是 falsy，会被当成没传
                # 从而落回默认 7 天 —— 永久队伍永远建不出来。
                raw_ttl = body.get("ttl")
                ttl = CODE_TTL_DEFAULT if raw_ttl is None else int(raw_ttl)
            except (TypeError, ValueError):
                _send(self, 400, {"ok": False, "error": "bad_request"})
                return
            # 三个语义要分清，不能合并成 `ttl <= 0`：
            #   不传      → 默认 7 天
            #   ttl == 0  → 永久（不过期，队长可随时关闭或轮换入队码）
            #   ttl <  0  → 非法输入，直接拒。当成永久等于把客户端 bug
            #               或恶意输入变成「永不回收的开放队伍」。
            if ttl < 0:
                _send(self, 400, {"ok": False, "error": "bad_request"})
                return
            permanent = ttl == 0
            if not permanent:
                ttl = max(TEAM_TTL_MIN, min(ttl, TEAM_TTL_MAX))
            nickname = str(body.get("nickname") or "队长")[:MAX_NICKNAME_LEN]
            if not captain_client_id or len(code_hash) != 64 or len(code_salt) != 64:
                _send(self, 400, {"ok": False, "error": "bad_request"})
                return
            self.STORE().record_create(ip)
            token = secrets.token_urlsafe(32)
            self.STORE().create_team(
                team_id, captain_client_id, code_hash, code_salt, ttl, permanent)
            self.STORE().add_member(team_id, captain_client_id, nickname, "captain",
                                  "approved", hash_token(token))
            _send(self, 200, {"ok": True, "team_id": team_id, "token": token,
                              "expires_at": 0 if permanent else time.time() + ttl,
                              "permanent": permanent})
            return

        # ---- /api/teams/join  输码加入 ----
        if parts == ["api", "teams", "join"]:
            code = str(body.get("code") or "").strip()
            team_id = str(body.get("team_id") or "").strip()
            client_id = str(body.get("client_id") or "").strip()
            nickname = str(body.get("nickname") or "队员")[:MAX_NICKNAME_LEN]
            # 码的形态：6 位数字（低熵档）或 8 位高熵码（32 字母表去易混字符）。
            # 以前只认 isdigit()，把客户端已有的 8 位高熵码模式整个废掉了
            # —— 队长能建队但队员永远进不来（400）。
            if not (team_id and client_id and _valid_code(code)):
                _send(self, 400, {"ok": False, "error": "bad_request"})
                return

            t = self.STORE().get_team(team_id)
            if not t or t["status"] != "open" or team_expired(t):
                _send(self, 410, {"ok": False, "error": "team_unavailable"})
                return
            if not self.STORE().check_rate_limit(team_id, ip):
                _send(self, 429, {"ok": False, "error": "too_many_attempts",
                                  "retry_after": JOIN_LOCK_SECONDS})
                return

            self.STORE().record_attempt(team_id, ip)
            # 145ms 的 scrypt 本身就是防枚举的一部分
            if not hmac.compare_digest(scrypt_key(code, t["code_salt"]), t["code_hash"]):
                _send(self, 403, {"ok": False, "error": "wrong_code"})
                return

            self.STORE().clear_attempts(team_id, ip)

            # 安全关键：join 只做「新成员加入」，绝不允许已存在的 client_id 重新认证。
            #
            # 为什么：client_id 是公开的（list_members 返回给每个成员），
            # 而 join 只验证组队码 —— 码恰恰是要分享给队员的。
            # 若允许重复 join，任何知道码的队员都能拿队长的 client_id 冒名顶替：
            # 走 add_member(..., "member", "approved", 新token) 会把队长 role 降级成 member
            # 并换掉其 token → 队长被踢出自己的队伍，队伍失去管理员。
            # 已成员应使用各自持久化的 team.json 里的 token 调其它端点。
            existing = self.STORE().get_member(team_id, client_id)
            if existing and existing["status"] == "kicked":
                _send(self, 403, {"ok": False, "error": "kicked"})
                return
            if existing:
                _send(self, 409, {"ok": False, "error": "already_member"})
                return
            if self.STORE().count_members(team_id) >= MAX_MEMBERS_PER_TEAM:
                _send(self, 409, {"ok": False, "error": "team_full"})
                return
            token = secrets.token_urlsafe(32)
            self.STORE().add_member(team_id, client_id, nickname, "member",
                                  "pending", hash_token(token))
            existing = self.STORE().get_member(team_id, client_id)
            # code_salt 必须返回：队员要用它 + code 派生 K_team。
            # salt 不是秘密（服务端本来就存着），返回无害；秘密只有 code 本身。
            _send(self, 200, {"ok": True, "team_id": team_id, "token": token,
                              "code_salt": t["code_salt"],
                              "status": existing["status"],
                              "members": self.STORE().list_members(team_id)})
            return

        # ---- /api/teams/<id>/<action> ----
        if len(parts) == 4 and parts[:2] == ["api", "teams"]:
            team_id, action = parts[2], parts[3]
            m, err = self._auth(team_id)
            if err:
                _send(self, err, {"ok": False, "error": "unauthorized"})
                return
            t = self.STORE().get_team(team_id)

            if action == "approve":      # 队长批准
                if m["role"] != "captain":
                    _send(self, 403, {"ok": False, "error": "captain_only"})
                    return
                cid = str(body.get("client_id") or "")
                if not cid or not self.STORE().get_member(team_id, cid):
                    _send(self, 404, {"ok": False, "error": "member_not_found"})
                    return
                self.STORE().set_member_status(team_id, cid, "approved")
                _send(self, 200, {"ok": True, "members": self.STORE().list_members(team_id)})
                return

            if action == "kick":         # 队长踢人
                if m["role"] != "captain":
                    _send(self, 403, {"ok": False, "error": "captain_only"})
                    return
                cid = str(body.get("client_id") or "")
                if cid == m["client_id"]:
                    _send(self, 400, {"ok": False, "error": "cannot_kick_self"})
                    return
                if not self.STORE().get_member(team_id, cid):
                    _send(self, 404, {"ok": False, "error": "member_not_found"})
                    return
                self.STORE().set_member_status(team_id, cid, "kicked")
                _send(self, 200, {"ok": True, "members": self.STORE().list_members(team_id)})
                return

            if action == "nickname":     # 队内改昵称
                nick = str(body.get("nickname") or "").strip()[:MAX_NICKNAME_LEN]
                if not nick:
                    _send(self, 400, {"ok": False, "error": "bad_request"})
                    return
                self.STORE().set_nickname(team_id, m["client_id"], nick)
                _send(self, 200, {"ok": True, "members": self.STORE().list_members(team_id)})
                return

            if action == "close":        # 队长关队（码随即失效）
                if m["role"] != "captain":
                    _send(self, 403, {"ok": False, "error": "captain_only"})
                    return
                self.STORE().close_team(team_id)
                _send(self, 200, {"ok": True, "status": "closed"})
                return

            if action == "rotate":       # 换码（旧码立即作废）
                if m["role"] != "captain":
                    _send(self, 403, {"ok": False, "error": "captain_only"})
                    return
                ch, cs = str(body.get("code_hash") or ""), str(body.get("code_salt") or "")
                if len(ch) != 64 or len(cs) != 64:
                    _send(self, 400, {"ok": False, "error": "bad_request"})
                    return
                self.STORE().rotate_code(team_id, ch, cs)
                _send(self, 200, {"ok": True})
                return

            if action == "packages":     # 上传密文包（服务端无法解密）
                # 共享池：任何已批准成员都能贡献，不只是队长。
                # 队长与队员的差别在于**白名单**（客户端侧），
                # 不在于能不能往池子里放东西。
                if m["status"] != "approved":
                    _send(self, 403, {"ok": False, "error": "not_approved"})
                    return
                if not t or t["status"] != "open":
                    _send(self, 410, {"ok": False, "error": "team_unavailable"})
                    return
                target = str(body.get("target_client_id") or "")
                pname = str(body.get("provider_name") or "")[:MAX_PROVIDER_NAME_LEN]
                try:
                    nonce = bytes.fromhex(str(body.get("nonce") or ""))
                    payload = bytes.fromhex(str(body.get("payload") or ""))
                except ValueError:
                    _send(self, 400, {"ok": False, "error": "bad_hex"})
                    return
                if len(nonce) != 12 or not payload or len(payload) > 65536 or not pname:
                    _send(self, 400, {"ok": False, "error": "bad_request"})
                    return
                # target 为空 = 广播给全队（用 K_team 加密，任何人都能解）。
                # 非空时必须确实存在且已批准，否则密文永远没人能取走。
                if target:
                    tgt = self.STORE().get_member(team_id, target)
                    if not tgt or tgt["status"] != "approved":
                        _send(self, 404, {"ok": False, "error": "member_not_found"})
                        return
                if not self.STORE().add_package(
                        team_id, target, m["client_id"], pname, payload, nonce):
                    _send(self, 409, {"ok": False, "error": "package_limit"})
                    return
                _send(self, 200, {"ok": True, "stored": self.STORE().count_packages(team_id)})
                return

            if action == "usage":        # 队员上报用量（只有数字，没有内容）
                if m["status"] != "approved":
                    _send(self, 403, {"ok": False, "error": "not_approved"})
                    return
                items = body.get("items") or []
                if not isinstance(items, list) or len(items) > MAX_USAGE_BATCH:
                    _send(self, 400, {"ok": False, "error": "bad_request"})
                    return
                clean = []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    try:
                        clean.append({
                            "ts": float(it.get("ts") or time.time()),
                            "provider": str(it.get("provider") or "")[:64],
                            "model": str(it.get("model") or "")[:128],
                            "pt": max(0, int(it.get("pt") or 0)),
                            "ct": max(0, int(it.get("ct") or 0)),
                            "tt": max(0, int(it.get("tt") or 0)),
                        })
                    except (TypeError, ValueError):
                        continue
                if clean:
                    self.STORE().add_usage(team_id, m["client_id"], clean)
                _send(self, 200, {"ok": True, "accepted": len(clean)})
                return

        _send(self, 404, {"ok": False, "error": "not_found"})


def main():
    if len(sys.argv) < 2:
        print("用法: coordinator.py <data.db> [port]", file=sys.stderr)
        sys.exit(2)
    db_path = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5022

    global _store
    _store = Store(db_path)
    store = _store

    # 启动时先清一次，之后每小时清一次过期队伍。
    # 不清理的话：数据库无限增长；且「7 天 TTL 防离线枚举」失效 ——
    # 过期队伍的 code_hash 仍在库里，拿到 db 文件依然能离线破解。
    purged = store.purge_expired()
    if purged:
        sys.stderr.write("启动清理：删除过期队伍 %d 个\n" % purged)

    def _purge_loop():
        while True:
            time.sleep(3600)
            try:
                n = store.purge_expired()
                if n:
                    sys.stderr.write("定期清理：删除过期队伍 %d 个\n" % n)
                    sys.stderr.flush()
            except Exception as exc:          # 清理失败不能拖垮服务
                sys.stderr.write("清理失败: %r\n" % (exc,))
                sys.stderr.flush()

    threading.Thread(target=_purge_loop, daemon=True).start()

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True

    def _stop(signum, frame):
        sys.stderr.write("收到信号，退出\n")
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sys.stderr.write("组队协调服务已启动: http://127.0.0.1:%d/health  db=%s\n" % (port, db_path))
    sys.stderr.flush()
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        srv.server_close()
        store.conn.close()


if __name__ == "__main__":
    main()
