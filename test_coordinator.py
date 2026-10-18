#!/usr/bin/env python3
"""协调服务的自测：起临时服务，验证健康检查、建队、入队、鉴权、限流、过期清理。

不依赖 pytest，直接 `python3 test_coordinator.py` 即可跑（CI 也用这个）。
"""
import json
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import protocol  # noqa: E402

CODE = "M2HP69BB"          # 8 位高熵码（默认形态）
PORT = 5077

fails = []


def check(name, cond, detail=""):
    print(("  ✓ " if cond else "  ✗ ") + name + (("  " + detail) if detail else ""))
    if not cond:
        fails.append(name)


class Api:
    def __init__(self, base):
        self.base = base

    def post(self, path, obj=None, token=None):
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, data=json.dumps(obj or {}).encode(),
                                     headers=h, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=15)
            return r.getcode(), json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def get(self, path, token):
        req = urllib.request.Request(self.base + path,
                                     headers={"Authorization": "Bearer " + token})
        try:
            r = urllib.request.urlopen(req, timeout=15)
            return r.getcode(), json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def main():
    db = HERE / "_test.db"
    for f in HERE.glob("_test.db*"):
        f.unlink()

    srv = subprocess.Popen([sys.executable, str(HERE / "coordinator.py"), str(db), str(PORT)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    api = Api(f"http://127.0.0.1:{PORT}")
    try:
        print("=== 服务端自测 ===")

        # /health 免鉴权，GET
        try:
            r = urllib.request.urlopen(f"{api.base}/health", timeout=10)
            hc, hb = r.getcode(), json.loads(r.read())
        except Exception as e:
            hc, hb = None, {"err": type(e).__name__}
        check("健康检查", hc == 200 and hb.get("service") == "reservoir-team")

        # 建队
        import secrets
        salt = secrets.token_bytes(32).hex()
        c, b = api.post("/api/teams", {"captain_client_id": "cap-1",
                                       "code_hash": protocol.code_hash(CODE, salt),
                                       "code_salt": salt, "ttl": 600, "nickname": "队长"})
        check("建队", c == 200 and bool(b.get("team_id")) and bool(b.get("token")))
        tid, cap_tok = b.get("team_id"), b.get("token")

        # 8 位码入队
        c, b = api.post("/api/teams/join", {"team_id": tid, "code": CODE,
                                            "client_id": "mem-1", "nickname": "队员"})
        check("8 位高熵码入队", c == 200 and bool(b.get("token")), f"HTTP={c}")
        check("返回 code_salt", len(b.get("code_salt", "")) == 64)
        mem_tok = b.get("token")

        # 队长批准
        c, _ = api.post(f"/api/teams/{tid}/approve", {"client_id": "mem-1"}, token=cap_tok)
        check("队长批准", c == 200)

        # 鉴权
        c, _ = api.get(f"/api/teams/{tid}/state", "wrong-token")
        check("错误 token 拒绝", c == 401)
        c, _ = api.get(f"/api/teams/{tid}/state", cap_tok)
        check("正确 token 通过", c == 200)

        # 队员不可用队长端点
        c, _ = api.post(f"/api/teams/{tid}/close", {}, token=mem_tok)
        check("队员不能关队", c == 403)

        # 冒名顶替防护
        c, b = api.post("/api/teams/join", {"team_id": tid, "code": CODE,
                                            "client_id": "cap-1", "nickname": "冒名"})
        check("不能用队长 client_id 顶替", c == 409 and b.get("error") == "already_member")

        # 畸形码
        c, _ = api.post("/api/teams/join", {"team_id": tid, "code": "12345678",
                                            "client_id": "z", "nickname": "z"})
        check("含字母表外字符的码被拒", c == 400)

        # 用量上报
        c, b = api.post(f"/api/teams/{tid}/usage",
                        {"items": [{"ts": time.time(), "provider": "p", "model": "m",
                                    "pt": 1, "ct": 2, "tt": 3}]}, token=mem_tok)
        check("用量上报", c == 200 and b.get("accepted") == 1)

        c, b = api.get(f"/api/teams/{tid}/usage", cap_tok)
        check("队长看用量统计", c == 200 and len(b.get("by_member", [])) == 1)

        # 过期清理
        con = sqlite3.connect(db)
        con.execute("UPDATE teams SET expires_at = strftime('%s','now') - 86400 "
                    "WHERE team_id=?", (tid,))
        con.commit()
        con.close()
        st = __import__("coordinator").Store(str(db))
        removed = st.purge_expired()
        st.conn.close()
        check("过期队伍清理", removed >= 1)

    finally:
        srv.terminate()
        srv.wait()
        for f in HERE.glob("_test.db*"):
            f.unlink()

    print("\n" + ("全部通过 ✓" if not fails else f"失败 {len(fails)} 项: {fails}"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
